// =============================================================================
// cuda_integration.hpp — CUDA 内核的 C++ 集成层
//
// 提供与 CPU NttEngine 兼容的高层 GPU 接口:
//   - gpu_ntt_batch()       → 批量 NTT (替代 CPU ntt_dispatch)
//   - gpu_apply_twiddles()  → Twiddle 因子乘法
//   - gpu_transpose()       → 矩阵转置
//   - gpu_encode_to_bytes() → 域元素编码
//
// 内部维护一个静态 GPU 内存池, 首次调用时分配, 后续复用,
// 避免反复 cudaMalloc/cudaFree 的开销。
//
// 使用方式 (在 NTT 引擎中):
//   #ifdef WHIR_CUDA
//   if (size >= GPU_THRESHOLD) { gpu_ntt_batch(values, roots, size); return; }
//   #endif
//   // ... CPU 路径 ...
// =============================================================================

#pragma once

#ifdef WHIR_CUDA

#include "cuda_ntt.hpp"
#include <cstdint>
#include <memory>
#include <vector>

namespace whir::cuda {

// GPU 加速阈值: 元素数低于此值直接走 CPU (GPU 启动开销 > 收益)
static constexpr std::size_t GPU_NTT_THRESHOLD = 65536;   // 64K 元素
static constexpr std::size_t GPU_TWIDDLE_THRESHOLD = 4096; // twiddle 计算轻, 阈值低

// ===========================================================================
// GpuPool — 单例 GPU 内存池, 复用显存分配
//
// 管理三块缓冲区:
//   data_buf  — NTT / twiddle / transpose 用的 uint64_t 数组
//   roots_buf — 单位根表 (上传一次, 多次使用)
//   byte_buf  — 域元素编码输出 (uint8_t)
//
// 所有 buffer 按需扩张 (只增不减), 进程退出时自动释放.
// ===========================================================================
class GpuPool {
public:
    static GpuPool& instance() {
        static GpuPool pool;
        return pool;
    }

    /// 确保 data buffer ≥ n 个 uint64_t
    uint64_t* data(std::size_t n) {
        ensure_cap<uint64_t>(data_, data_cap_, n);
        return data_.get();
    }

    /// 确保 roots buffer ≥ n 个 uint64_t
    uint64_t* roots(std::size_t n) {
        ensure_cap<uint64_t>(roots_, roots_cap_, n);
        return roots_.get();
    }

    /// 确保 byte buffer ≥ n 个 uint8_t
    uint8_t* bytes(std::size_t n) {
        ensure_cap<uint8_t>(byte_, byte_cap_, n);
        return byte_.get();
    }

    /// 上传单位根表到 GPU
    void upload_roots(const uint64_t* host, std::size_t n) {
        uint64_t* d = roots(n);
        cudaMemcpy(d, host, n * sizeof(uint64_t), cudaMemcpyHostToDevice);
        roots_len_ = n;
    }

    std::size_t roots_len() const noexcept { return roots_len_; }

private:
    GpuPool() = default;

    struct CudaDeleter {
        void operator()(void* p) const { if (p) cudaFree(p); }
    };

    template <typename T>
    using CudaPtr = std::unique_ptr<T, CudaDeleter>;

    template <typename T>
    void ensure_cap(CudaPtr<T>& p, std::size_t& cap, std::size_t n) {
        if (n > cap) {
            cap = n;
            T* raw = nullptr;
            cudaMalloc(&raw, n * sizeof(T));
            p.reset(raw);
        }
    }

    CudaPtr<uint64_t> data_;
    CudaPtr<uint64_t> roots_;
    CudaPtr<uint8_t>  byte_;
    std::size_t data_cap_ = 0, roots_cap_ = 0, byte_cap_ = 0, roots_len_ = 0;
};

// ===========================================================================
// 高层 GPU 函数
// ===========================================================================

// ---- 内部辅助: sqrt_factor (同 CPU 端, 最大 2 的幂因子 ≤ √n) ----
inline std::size_t sqrt_factor_gpu(std::size_t n) {
    if (n <= 1) return 1;
    std::size_t r = 1;
    while (r * r * 4 <= n) r *= 2;
    return r;
}

// ---- 内部: GPU NTT dispatch (批量子变换, default stream 自动保序) ----
inline void gpu_ntt_dispatch(uint64_t* d_data, uint64_t* d_roots,
                             std::size_t blocks, std::size_t size) {
    if (size <= 1) return;
    std::size_t total = blocks * size;

    if (size == 2) {
        launch_ntt_radix2(d_data, d_roots, static_cast<uint32_t>(size), 1);
        return;
    }
    if (size == 4) {
        launch_ntt_radix4(d_data, d_roots, static_cast<uint32_t>(size), 1);
        return;
    }

    // 6-step Cooley-Tukey 分解: size = n1 × n2
    // CUDA default stream 保证 kernel 按 launch 顺序执行, 无需中间 sync
    std::size_t n1 = sqrt_factor_gpu(size);
    std::size_t n2 = size / n1;
    std::size_t block = size;

    for (std::size_t off = 0; off < total; off += block) {
        uint64_t* blk = d_data + off;
        launch_transpose(blk, n1, n2);              // 1. n1×n2 → n2×n1
        gpu_ntt_dispatch(blk, d_roots, n2, n1);    // 2. NTT(n1) × n2 行
        launch_transpose(blk, n2, n1);              // 3. n2×n1 → n1×n2
        launch_apply_twiddles(blk, d_roots, n1, n2, 1); // 4. twiddle
        gpu_ntt_dispatch(blk, d_roots, n1, n2);    // 5. NTT(n2) × n1 行
        launch_transpose(blk, n1, n2);              // 6. n1×n2 → n2×n1
    }
}

/// GPU 批量 NTT: 6-step Cooley-Tukey
inline void gpu_ntt_batch(uint64_t* values, const uint64_t* roots,
                          std::size_t total, std::size_t size) {
    auto& pool = GpuPool::instance();
    uint64_t* d_data = pool.data(total);

    cudaMemcpy(d_data, values, total * sizeof(uint64_t), cudaMemcpyHostToDevice);
    gpu_ntt_dispatch(d_data, pool.roots(pool.roots_len()), total / size, size);
    cudaDeviceSynchronize();  // 唯一同步点: 等待所有 kernel 完成
    cudaMemcpy(values, d_data, total * sizeof(uint64_t), cudaMemcpyDeviceToHost);
}

/// GPU 域元素编码: 每个 uint64_t (Montgomery) → 8 LE 字节
inline void gpu_encode_to_bytes(const uint64_t* values, uint8_t* out, std::size_t count) {
    auto& pool = GpuPool::instance();
    uint64_t* d_vals = pool.data(count);
    uint8_t*  d_out  = pool.bytes(count * 8);

    cudaMemcpy(d_vals, values, count * sizeof(uint64_t), cudaMemcpyHostToDevice);
    launch_encode_to_bytes(d_vals, d_out, static_cast<uint32_t>(count));
    cudaDeviceSynchronize();
    cudaMemcpy(out, d_out, count * 8, cudaMemcpyDeviceToHost);
}

} // namespace whir::cuda
#endif // WHIR_CUDA
