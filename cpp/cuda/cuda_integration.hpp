// =============================================================================
// cuda_integration.hpp — CUDA 内核的 C++ 集成层
//
// 提供与 CPU NttEngine 兼容的高层 GPU 接口:
//   - gpu_ntt_batch()       → 批量 NTT (替代 CPU ntt_dispatch)
//   - gpu_apply_twiddles()  → Twiddle 因子乘法
//   - gpu_transpose()       → 矩阵转置
//   - gpu_encode_to_bytes() → 域元素编码
//
// 内部维护一个静态 GPU 内存池: 首次调用时分配, 后续复用,
// 避免反复 cudaMalloc/cudaFree 的开销.
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
#include "include/whir/profiling.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace whir::cuda {

// GPU 加速阈值: 元素数低于此值直接走 CPU (GPU 启动开销 > 收益)
static constexpr std::size_t GPU_NTT_THRESHOLD = 65536;   // 64K 元素
static constexpr std::size_t GPU_TWIDDLE_THRESHOLD = 4096; // twiddle 计算轻量, 阈值低

struct GpuNttTiming {
    float malloc_ms = 0.0f;
    float h2d_ms = 0.0f;
    float kernel_ms = 0.0f;
    float d2h_ms = 0.0f;
    float total_ms = 0.0f;
    bool used_gpu = false;
};

inline bool& gpu_dispatch_enabled_flag() {
    static bool enabled = [] {
        const char* v = std::getenv("WHIR_CUDA_DISABLE");
        return !(v && (v[0] == '1' || v[0] == 't' || v[0] == 'T' || v[0] == 'y' || v[0] == 'Y'));
    }();
    return enabled;
}

inline std::size_t& gpu_ntt_threshold_value() {
    static std::size_t threshold = GPU_NTT_THRESHOLD;
    return threshold;
}

inline GpuNttTiming& last_ntt_timing_value() {
    static GpuNttTiming timing;
    return timing;
}

inline bool gpu_dispatch_enabled() {
    return gpu_dispatch_enabled_flag();
}

inline void set_gpu_dispatch_enabled(bool enabled) {
    gpu_dispatch_enabled_flag() = enabled;
}


inline std::size_t gpu_ntt_threshold() {
    return gpu_ntt_threshold_value();
}

inline void set_gpu_ntt_threshold(std::size_t threshold) {
    gpu_ntt_threshold_value() = threshold;
}

inline GpuNttTiming last_ntt_timing() {
    return last_ntt_timing_value();
}

inline void cuda_warmup() {
    CUDA_CHECK(cudaFree(nullptr));
}

inline float elapsed_ms(cudaEvent_t start, cudaEvent_t stop) {
    float ms = 0.0f;
    CUDA_CHECK(cudaEventElapsedTime(&ms, start, stop));
    return ms;
}

class ScopedCudaEvents {
public:
    ScopedCudaEvents() {
        CUDA_CHECK(cudaEventCreate(&start_));
        CUDA_CHECK(cudaEventCreate(&stop_));
    }
    ~ScopedCudaEvents() {
        cudaEventDestroy(start_);
        cudaEventDestroy(stop_);
    }
    cudaEvent_t start() const noexcept { return start_; }
    cudaEvent_t stop() const noexcept { return stop_; }

private:
    cudaEvent_t start_ = nullptr;
    cudaEvent_t stop_ = nullptr;
};

class ScopedCudaStream {
public:
    ScopedCudaStream() {
        CUDA_CHECK(cudaStreamCreateWithFlags(&stream_, cudaStreamNonBlocking));
    }
    ~ScopedCudaStream() {
        if (stream_) cudaStreamDestroy(stream_);
    }
    cudaStream_t get() const noexcept { return stream_; }

private:
    cudaStream_t stream_ = nullptr;
};

// ===========================================================================
// GpuPool — 单例 GPU 内存池, 复用显存分配
//
// 管理三块缓冲区:
//   data_buf  — NTT / twiddle / transpose 用的 uint64_t 数组
//   roots_buf — 单位根表 (上传一次, 多次使用)
//   byte_buf  — 域元素编码输出 (uint8_t)
//
// 所有 buffer 按需扩展 (只增不减), 进程退出时自动释放.
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

    /// 确保 hash output byte buffer ≥ n 个字节
    uint8_t* hashes(std::size_t n) {
        ensure_cap<uint8_t>(hash_, hash_cap_, n);
        return hash_.get();
    }

    /// 确保 Merkle tree byte buffer ≥ n 个字节
    uint8_t* merkle(std::size_t n) {
        ensure_cap<uint8_t>(merkle_, merkle_cap_, n);
        return merkle_.get();
    }

    uint8_t* pinned(std::size_t n) {
        ensure_host_cap(pinned_, pinned_cap_, n);
        return pinned_.get();
    }

    /// 确保输入 uint64_t buffer ≥ n 个元素
    uint64_t* input(std::size_t n) {
        ensure_cap<uint64_t>(input_, input_cap_, n);
        return input_.get();
    }

    /// 确保临时 uint64_t buffer ≥ n 个元素
    uint64_t* temp(std::size_t n) {
        ensure_cap<uint64_t>(scratch_, scratch_cap_, n);
        return scratch_.get();
    }

    uint64_t* component0(std::size_t n) {
        ensure_cap<uint64_t>(component0_, component0_cap_, n);
        return component0_.get();
    }

    uint64_t* component1(std::size_t n) {
        ensure_cap<uint64_t>(component1_, component1_cap_, n);
        return component1_.get();
    }

    uint64_t* component2(std::size_t n) {
        ensure_cap<uint64_t>(component2_, component2_cap_, n);
        return component2_.get();
    }

    /// 上传单位根表到 GPU
    void upload_roots(const uint64_t* host, std::size_t n) {
        uint64_t* d = roots(n);
        CUDA_CHECK(cudaMemcpy(d, host, n * sizeof(uint64_t), cudaMemcpyHostToDevice));
        roots_len_ = n;
        roots_host_ = host;
    }

    std::size_t roots_len() const noexcept { return roots_len_; }
    const uint64_t* roots_host() const noexcept { return roots_host_; }

    void reset_alloc_timing() noexcept { last_alloc_ms_ = 0.0; }
    double last_alloc_ms() const noexcept { return last_alloc_ms_; }

private:
    GpuPool() = default;

    struct CudaDeleter {
        void operator()(void* p) const { if (p) cudaFree(p); }
    };

    struct CudaHostDeleter {
        void operator()(void* p) const { if (p) cudaFreeHost(p); }
    };

    template <typename T>
    using CudaPtr = std::unique_ptr<T, CudaDeleter>;
    using HostPtr = std::unique_ptr<uint8_t, CudaHostDeleter>;

    template <typename T>
    void ensure_cap(CudaPtr<T>& p, std::size_t& cap, std::size_t n) {
        if (n > cap) {
            const auto t0 = std::chrono::steady_clock::now();
            cap = n;
            T* raw = nullptr;
            CUDA_CHECK(cudaMalloc(&raw, n * sizeof(T)));
            p.reset(raw);
            last_alloc_ms_ += std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t0).count();
        }
    }

    void ensure_host_cap(HostPtr& p, std::size_t& cap, std::size_t n) {
        if (n > cap) {
            const auto t0 = std::chrono::steady_clock::now();
            cap = n;
            uint8_t* raw = nullptr;
            CUDA_CHECK(cudaHostAlloc(&raw, n, cudaHostAllocDefault));
            p.reset(raw);
            last_alloc_ms_ += std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t0).count();
        }
    }

    CudaPtr<uint64_t> data_;
    CudaPtr<uint64_t> roots_;
    CudaPtr<uint64_t> scratch_;
    CudaPtr<uint64_t> input_;
    CudaPtr<uint64_t> component0_;
    CudaPtr<uint64_t> component1_;
    CudaPtr<uint64_t> component2_;
    CudaPtr<uint8_t>  byte_;
    CudaPtr<uint8_t>  hash_;
    CudaPtr<uint8_t>  merkle_;
    HostPtr pinned_;
    std::size_t data_cap_ = 0, roots_cap_ = 0, scratch_cap_ = 0, input_cap_ = 0;
    std::size_t component0_cap_ = 0, component1_cap_ = 0, component2_cap_ = 0;
    std::size_t byte_cap_ = 0, hash_cap_ = 0, merkle_cap_ = 0, roots_len_ = 0;
    std::size_t pinned_cap_ = 0;
    const uint64_t* roots_host_ = nullptr;
    double last_alloc_ms_ = 0.0;
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
// 返回值指向包含结果的缓冲区。递归层在 d_data 与 d_scratch 之间 ping-pong,
// 避免 transpose 后再做整块 cudaMemcpyDeviceToDevice.
inline uint64_t* gpu_ntt_dispatch(uint64_t* d_data, uint64_t* d_scratch, uint64_t* d_roots,
                                  std::size_t roots_len, std::size_t blocks, std::size_t size,
                                  cudaStream_t stream = nullptr) {
    if (size <= 1) return d_data;
    std::size_t total = blocks * size;

    if (size == 2) {
        launch_ntt_radix2(d_data, d_roots, static_cast<uint32_t>(size),
                          static_cast<uint32_t>(roots_len / size),
                          static_cast<uint32_t>(blocks), stream);
        return d_data;
    }
    if (size == 4) {
        launch_ntt_radix4(d_data, d_roots, static_cast<uint32_t>(size),
                          static_cast<uint32_t>(roots_len / size),
                          static_cast<uint32_t>(blocks), stream);
        return d_data;
    }

    // 6-step Cooley-Tukey decomposition; the supplied stream preserves launch order.
    std::size_t n1 = sqrt_factor_gpu(size);
    std::size_t n2 = size / n1;
    launch_transpose(d_data, d_scratch, static_cast<uint32_t>(n1), static_cast<uint32_t>(n2),
                     static_cast<uint32_t>(blocks), stream);

    uint64_t* step2 = gpu_ntt_dispatch(
        d_scratch, d_data, d_roots, roots_len, blocks * n2, n1, stream);

    uint64_t* step3 = (step2 == d_data) ? d_scratch : d_data;
    launch_transpose(step2, step3, static_cast<uint32_t>(n2), static_cast<uint32_t>(n1),
                     static_cast<uint32_t>(blocks), stream);

    launch_apply_twiddles(step3, d_roots, static_cast<uint32_t>(n1), static_cast<uint32_t>(n2),
                          static_cast<uint32_t>(roots_len / size),
                          static_cast<uint32_t>(blocks), stream);

    uint64_t* step5_scratch = (step3 == d_data) ? d_scratch : d_data;
    uint64_t* step5 = gpu_ntt_dispatch(
        step3, step5_scratch, d_roots, roots_len, blocks * n1, n2, stream);

    uint64_t* out = (step5 == d_data) ? d_scratch : d_data;
    launch_transpose(step5, out, static_cast<uint32_t>(n1), static_cast<uint32_t>(n2),
                     static_cast<uint32_t>(blocks), stream);
    return out;
}

/// GPU 批量 NTT: 6-step Cooley-Tukey
inline void gpu_ntt_batch(uint64_t* values, const uint64_t* roots,
                          std::size_t total, std::size_t size) {
    (void)roots;
    auto& pool = GpuPool::instance();
    pool.reset_alloc_timing();
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    timing.malloc_ms = static_cast<float>(pool.last_alloc_ms());
    ScopedCudaEvents ev;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(d_data, values, total * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.h2d_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    uint64_t* result = gpu_ntt_dispatch(
        d_data, d_scratch, pool.roots(pool.roots_len()), pool.roots_len(), total / size, size);
    CUDA_CHECK(cudaDeviceSynchronize());  // 唯一同步点, 等待所有 kernel 完成
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(values, result, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_malloc", timing.malloc_ms);
    whir::profile::record("cuda", total, "gpu_h2d", timing.h2d_ms);
    whir::profile::record("cuda", total, "gpu_kernel", timing.kernel_ms);
    whir::profile::record("cuda", total, "gpu_d2h", timing.d2h_ms);
    whir::profile::record("cuda", total, "gpu_total", timing.total_ms + timing.malloc_ms);
}

/// GPU 批量 NTT 后立即转置: 输入按 blocks×ntt_size 排列,
/// 输出按 ntt_size×blocks 行主序排列
inline void gpu_ntt_batch_transpose(uint64_t* values, const uint64_t* roots,
                                    std::size_t total, std::size_t ntt_size,
                                    std::size_t rows, std::size_t cols) {
    (void)roots;
    auto& pool = GpuPool::instance();
    pool.reset_alloc_timing();
    uint64_t* d_data = pool.data(total);
    uint64_t* d_tmp = pool.temp(total);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    timing.malloc_ms = static_cast<float>(pool.last_alloc_ms());
    ScopedCudaEvents ev;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(d_data, values, total * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.h2d_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    uint64_t* result = gpu_ntt_dispatch(
        d_data, d_tmp, pool.roots(pool.roots_len()), pool.roots_len(), total / ntt_size, ntt_size);
    uint64_t* transposed = (result == d_data) ? d_tmp : d_data;
    launch_transpose(result, transposed, static_cast<uint32_t>(rows), static_cast<uint32_t>(cols), 1);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(values, transposed, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_malloc", timing.malloc_ms);
    whir::profile::record("cuda", total, "gpu_h2d", timing.h2d_ms);
    whir::profile::record("cuda", total, "gpu_kernel", timing.kernel_ms);
    whir::profile::record("cuda", total, "gpu_d2h", timing.d2h_ms);
    whir::profile::record("cuda", total, "gpu_total", timing.total_ms + timing.malloc_ms);
}

/// GPU Reed-Solomon 编码: 紧凑系数上传 → GPU 零填充打包 → 批量 NTT → 最终转置
inline void gpu_interleaved_rs_encode(const uint64_t* coeffs, uint64_t* out,
                                      std::size_t num_polys,
                                      std::size_t poly_size,
                                      std::size_t codeword_length,
                                      std::size_t interleaving_depth) {
    auto& pool = GpuPool::instance();
    pool.reset_alloc_timing();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t total = rows * codeword_length;
    uint64_t* d_coeffs = pool.input(coeff_total);
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    timing.malloc_ms = static_cast<float>(pool.last_alloc_ms());
    ScopedCudaEvents ev;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(d_coeffs, coeffs, coeff_total * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.h2d_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemset(d_data, 0, total * sizeof(uint64_t)));
    launch_pack_rs_coeffs(d_coeffs, d_data,
                          static_cast<uint32_t>(poly_size),
                          static_cast<uint32_t>(codeword_length),
                          static_cast<uint32_t>(interleaving_depth),
                          static_cast<uint32_t>(num_polys));
    uint64_t* result = gpu_ntt_dispatch(
        d_data, d_scratch, pool.roots(pool.roots_len()), pool.roots_len(), rows, codeword_length);
    uint64_t* transposed = (result == d_data) ? d_scratch : d_data;
    launch_transpose(result, transposed, static_cast<uint32_t>(rows),
                     static_cast<uint32_t>(codeword_length), 1);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out, transposed, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_malloc", timing.malloc_ms);
    whir::profile::record("cuda", total, "gpu_h2d", timing.h2d_ms);
    whir::profile::record("cuda", total, "gpu_kernel", timing.kernel_ms);
    whir::profile::record("cuda", total, "gpu_d2h", timing.d2h_ms);
    whir::profile::record("cuda", total, "gpu_total", timing.total_ms + timing.malloc_ms);
}

struct GpuRsComponentTiming {
    float ntt_ms = 0.0f;
};

//把一个Goldilocks分量系数coeffs上传到GPU，在GPU上做RS编码/NTT扩展，然后转置成目标布局
inline uint64_t* gpu_rs_encode_component_to_device(
    const uint64_t* coeffs,
    uint64_t* d_component_out,
    std::size_t num_polys,
    std::size_t poly_size,
    std::size_t codeword_length,
    std::size_t interleaving_depth,
    GpuRsComponentTiming* component_timing = nullptr
) {
    auto& pool = GpuPool::instance();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t total = rows * codeword_length;
    uint64_t* d_coeffs = pool.input(coeff_total);
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    ScopedCudaEvents ev;

    //CPU系数——> GPU d_coeffs
    CUDA_CHECK(cudaMemcpy(d_coeffs, coeffs, coeff_total * sizeof(uint64_t), cudaMemcpyHostToDevice));
    //d_data清零
    CUDA_CHECK(cudaMemset(d_data, 0, total * sizeof(uint64_t)));

    //把d_data重新排列到d_coeffs里 ,同时补0
    launch_pack_rs_coeffs(d_coeffs, d_data,
                          static_cast<uint32_t>(poly_size),
                          static_cast<uint32_t>(codeword_length),
                          static_cast<uint32_t>(interleaving_depth),
                          static_cast<uint32_t>(num_polys));

    //NTT计时时间
    CUDA_CHECK(cudaEventRecord(ev.start()));
    //NTT
    uint64_t* result = gpu_ntt_dispatch(
        //d_scratch是临时缓冲区，因为GPU NTT采用ping-pong buffer方式,两个缓冲区来回切换
        d_data, d_scratch, pool.roots(pool.roots_len()), pool.roots_len(), rows, codeword_length);
    //如果NTT结果在d_data，那转置结果就写到d_scratch
    //如果NTT结果在d_scratch,那转置结果就写到d_data
    uint64_t* transposed = (result == d_data) ? d_scratch : d_data;
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    if (component_timing != nullptr) {
        component_timing->ntt_ms += elapsed_ms(ev.start(), ev.stop());
    }

    //转置
    launch_transpose(result, transposed, static_cast<uint32_t>(rows),
                     static_cast<uint32_t>(codeword_length), 1);

    CUDA_CHECK(cudaMemcpy(d_component_out, transposed, total * sizeof(uint64_t), cudaMemcpyDeviceToDevice));
    return d_component_out;
}

//Goldilocks域
//RS encode+blake3 hash
inline bool gpu_interleaved_rs_encode_blake3_matrix_leaves(const uint64_t* coeffs,
                                                           uint64_t* out_matrix,
                                                           uint8_t* out_hashes,
                                                           std::size_t num_polys,
                                                           std::size_t poly_size,
                                                           std::size_t codeword_length,
                                                           std::size_t interleaving_depth) {
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t message_size = rows * sizeof(uint64_t);
    if (message_size == 0 || (message_size % 64) != 0 || message_size > 1024) {
        return false;
    }

    auto& pool = GpuPool::instance();
    pool.reset_alloc_timing();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t total = rows * codeword_length;
    (void)pool.input(coeff_total);
    (void)pool.data(total);
    (void)pool.temp(total);
    uint64_t* d_matrix = pool.component0(total);
    uint8_t* d_hashes = pool.hashes(codeword_length * 32);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    timing.malloc_ms = static_cast<float>(pool.last_alloc_ms());
    ScopedCudaEvents ev;

    GpuRsComponentTiming component_timing;
    gpu_rs_encode_component_to_device(
        coeffs, d_matrix, num_polys, poly_size, codeword_length, interleaving_depth,
        &component_timing);
    const float ntt_ms = component_timing.ntt_ms;

    //hash计时开始
    CUDA_CHECK(cudaEventRecord(ev.start()));
    //计算hash
    launch_blake3_hash_goldilocks_rows(d_matrix, d_hashes, static_cast<uint32_t>(rows),
                                       static_cast<uint32_t>(codeword_length));
    //hash计时结束
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    const float hash_ms = elapsed_ms(ev.start(), ev.stop());
    timing.kernel_ms = ntt_ms + hash_ms;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out_matrix, d_matrix, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(out_hashes, d_hashes, codeword_length * 32, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_blake3_leaves_ntt", ntt_ms);
    whir::profile::record("cuda", total, "gpu_blake3_leaves_hash", hash_ms);
    return true;
}

inline bool gpu_interleaved_rs_encode_blake3_ext2_matrix_leaves(
    const uint64_t* coeff0,
    const uint64_t* coeff1,
    uint64_t* out0,
    uint64_t* out1,
    uint8_t* out_hashes,
    std::size_t num_polys,
    std::size_t poly_size,
    std::size_t codeword_length,
    std::size_t interleaving_depth
) {
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t message_size = rows * 16;
    if (message_size == 0 || (message_size % 64) != 0 || message_size > 1024) {
        return false;
    }

    auto& pool = GpuPool::instance();
    pool.reset_alloc_timing();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t total = rows * codeword_length;
    (void)pool.input(coeff_total);
    (void)pool.data(total);
    (void)pool.temp(total);
    uint64_t* d_c0 = pool.component0(total);
    uint64_t* d_c1 = pool.component1(total);
    uint8_t* d_bytes = pool.bytes(total * 16);
    uint8_t* d_hashes = pool.hashes(codeword_length * 32);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    timing.malloc_ms = static_cast<float>(pool.last_alloc_ms());
    ScopedCudaEvents ev;

    GpuRsComponentTiming component_timing;
    gpu_rs_encode_component_to_device(
        coeff0, d_c0, num_polys, poly_size, codeword_length, interleaving_depth,
        &component_timing);
    gpu_rs_encode_component_to_device(
        coeff1, d_c1, num_polys, poly_size, codeword_length, interleaving_depth,
        &component_timing);
    const float ntt_ms = component_timing.ntt_ms;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    launch_encode_ext2_to_bytes(d_c0, d_c1, d_bytes, static_cast<uint32_t>(total));
    launch_blake3_hash_many(d_bytes, d_hashes, static_cast<uint32_t>(message_size),
                            static_cast<uint32_t>(codeword_length));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    const float hash_ms = elapsed_ms(ev.start(), ev.stop());
    timing.kernel_ms = ntt_ms + hash_ms;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out0, d_c0, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(out1, d_c1, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(out_hashes, d_hashes, codeword_length * 32, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_blake3_ext2_leaves_ntt", ntt_ms);
    whir::profile::record("cuda", total, "gpu_blake3_ext2_leaves_hash", hash_ms);
    return true;
}

//GoldilocksExt3域函数
inline bool gpu_interleaved_rs_encode_blake3_ext3_matrix_leaves(
    const uint64_t* coeff0,
    const uint64_t* coeff1,
    const uint64_t* coeff2,
    uint64_t* out0,
    uint64_t* out1,
    uint64_t* out2,
    uint8_t* out_hashes,
    std::size_t num_polys,
    std::size_t poly_size,
    std::size_t codeword_length,
    std::size_t interleaving_depth
) {
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t message_size = rows * 24;
    if (message_size == 0 || (message_size % 64) != 0 || message_size > 1024) {
        return false;
    }

    auto& pool = GpuPool::instance();
    pool.reset_alloc_timing();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t total = rows * codeword_length;
    (void)pool.input(coeff_total);
    (void)pool.data(total);
    (void)pool.temp(total);
    uint64_t* d_c0 = pool.component0(total);
    uint64_t* d_c1 = pool.component1(total);
    uint64_t* d_c2 = pool.component2(total);
    uint8_t* d_bytes = pool.bytes(total * 24);
    uint8_t* d_hashes = pool.hashes(codeword_length * 32);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    timing.malloc_ms = static_cast<float>(pool.last_alloc_ms());
    ScopedCudaEvents ev;

    //Ext3 ntt = c0 ntt + c1 ntt + c2 ntt
    GpuRsComponentTiming component_timing;
    gpu_rs_encode_component_to_device(
        coeff0, d_c0, num_polys, poly_size, codeword_length, interleaving_depth,
        &component_timing);
    gpu_rs_encode_component_to_device(
        coeff1, d_c1, num_polys, poly_size, codeword_length, interleaving_depth,
        &component_timing);
    gpu_rs_encode_component_to_device(
        coeff2, d_c2, num_polys, poly_size, codeword_length, interleaving_depth,
        &component_timing);
    const float ntt_ms = component_timing.ntt_ms;

    //hash开始计时
    CUDA_CHECK(cudaEventRecord(ev.start()));
    launch_encode_ext3_to_bytes(d_c0, d_c1, d_c2, d_bytes, static_cast<uint32_t>(total));
    launch_blake3_hash_many(d_bytes, d_hashes, static_cast<uint32_t>(message_size),
                            static_cast<uint32_t>(codeword_length));
    CUDA_CHECK(cudaEventRecord(ev.stop())); //hash计时结束
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    const float hash_ms = elapsed_ms(ev.start(), ev.stop());
    timing.kernel_ms = ntt_ms + hash_ms;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out0, d_c0, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(out1, d_c1, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(out2, d_c2, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(out_hashes, d_hashes, codeword_length * 32, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_blake3_ext3_leaves_ntt", ntt_ms);
    whir::profile::record("cuda", total, "gpu_blake3_ext3_leaves_hash", hash_ms);
    return true;
}

inline std::size_t merkle_layers_for_size(std::size_t size) noexcept {
    if (size <= 1) return 0;
    std::size_t pow = 1, k = 0;
    while (pow < size) {
        pow <<= 1;
        ++k;
    }
    return k;
}

inline void gpu_sha256_merkle_tree_device(const uint8_t* d_leaves,
                                          std::size_t num_leaves,
                                          uint8_t* d_nodes) {
    const std::size_t layers = merkle_layers_for_size(num_leaves);
    const std::size_t leaf_layer_size = std::size_t{1} << layers;
    const std::size_t num_nodes = (std::size_t{1} << (layers + 1)) - 1;

    CUDA_CHECK(cudaMemset(d_nodes, 0, num_nodes * 32));
    if (num_leaves > 0) {
        CUDA_CHECK(cudaMemcpy(d_nodes, d_leaves, num_leaves * 32, cudaMemcpyDeviceToDevice));
    }

    std::size_t prev_off = 0;
    std::size_t prev_len = leaf_layer_size;
    std::size_t curr_off = leaf_layer_size;
    while (prev_len > 1) {
        const std::size_t curr_len = prev_len / 2;
        launch_sha256_hash_many(d_nodes + prev_off * 32, d_nodes + curr_off * 32,
                                64, static_cast<uint32_t>(curr_len));
        prev_off = curr_off;
        prev_len = curr_len;
        curr_off += curr_len;
    }
}

inline void gpu_blake3_merkle_tree_device(const uint8_t* d_leaves,
                                          std::size_t num_leaves,
                                          uint8_t* d_nodes,
                                          cudaStream_t stream) {
    const std::size_t layers = merkle_layers_for_size(num_leaves);
    const std::size_t leaf_layer_size = std::size_t{1} << layers;
    const std::size_t num_nodes = (std::size_t{1} << (layers + 1)) - 1;

    CUDA_CHECK(cudaMemsetAsync(d_nodes, 0, num_nodes * 32, stream));
    if (num_leaves > 0) {
        CUDA_CHECK(cudaMemcpyAsync(d_nodes, d_leaves, num_leaves * 32,
                                   cudaMemcpyDeviceToDevice, stream));
    }

    std::size_t prev_off = 0;
    std::size_t prev_len = leaf_layer_size;
    std::size_t curr_off = leaf_layer_size;
    while (prev_len > 1) {
        const std::size_t curr_len = prev_len / 2;
        launch_blake3_hash_many(d_nodes + prev_off * 32, d_nodes + curr_off * 32,
                                64, static_cast<uint32_t>(curr_len), stream);
        prev_off = curr_off;
        prev_len = curr_len;
        curr_off += curr_len;
    }
}

inline std::vector<uint64_t> merkle_hint_node_indices(std::size_t num_leaves,
                                                      std::span<const std::size_t> raw_indices) {
    const std::size_t layers = merkle_layers_for_size(num_leaves);
    const std::size_t leaf_layer_size = std::size_t{1} << layers;
    std::vector<std::size_t> indices(raw_indices.begin(), raw_indices.end());
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());

    std::vector<uint64_t> hint_nodes;
    std::size_t layer_off = 0;
    std::size_t layer_len = leaf_layer_size;
    while (layer_len > 1) {
        std::vector<std::size_t> next_indices;
        next_indices.reserve(indices.size());
        for (std::size_t k = 0; k < indices.size();) {
            const std::size_t a = indices[k];
            const bool merge = (k + 1 < indices.size()) && (indices[k + 1] == (a ^ 1));
            if (merge) {
                next_indices.push_back(a >> 1);
                k += 2;
            } else {
                hint_nodes.push_back(static_cast<uint64_t>(layer_off + (a ^ 1)));
                next_indices.push_back(a >> 1);
                k += 1;
            }
        }
        indices = std::move(next_indices);
        layer_off += layer_len;
        layer_len >>= 1;
    }
    return hint_nodes;
}

/// GPU SHA-256 Merkle tree build.
///
/// 输入 leaves 为 num_leaves 个 32B hash。设备端补齐零 hash 后逐层执行
/// parent = SHA256(left || right)。如果 out_nodes 非空，回传完整 witness nodes,
/// 否则只回传 root.
inline void gpu_sha256_merkle_tree(const uint8_t* leaves,
                                   std::size_t num_leaves,
                                   uint8_t* out_root,
                                   uint8_t* out_nodes = nullptr) {
    const std::size_t layers = merkle_layers_for_size(num_leaves);
    const std::size_t leaf_layer_size = std::size_t{1} << layers;
    const std::size_t num_nodes = (std::size_t{1} << (layers + 1)) - 1;
    auto& pool = GpuPool::instance();
    uint8_t* d_leaves = pool.hashes(num_leaves * 32);
    uint8_t* d_nodes = pool.merkle(num_nodes * 32);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    ScopedCudaEvents ev;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    if (num_leaves > 0) {
        CUDA_CHECK(cudaMemcpy(d_leaves, leaves, num_leaves * 32, cudaMemcpyHostToDevice));
    }
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.h2d_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    gpu_sha256_merkle_tree_device(d_leaves, num_leaves, d_nodes);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    if (out_nodes != nullptr) {
        CUDA_CHECK(cudaMemcpy(out_nodes, d_nodes, num_nodes * 32, cudaMemcpyDeviceToHost));
    } else {
        CUDA_CHECK(cudaMemcpy(out_root, d_nodes + (num_nodes - 1) * 32, 32, cudaMemcpyDeviceToHost));
    }
    if (out_nodes != nullptr && out_root != nullptr) {
        std::copy(out_nodes + (num_nodes - 1) * 32, out_nodes + num_nodes * 32, out_root);
    }
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
}

/// GPU SHA-256 Merkle tree open path.
///
/// 构建 device Merkle tree，但只回传 root 和按 CPU open_path 顺序排列的 sibling hints.
inline void gpu_sha256_merkle_open_path(const uint8_t* leaves,
                                        std::size_t num_leaves,
                                        std::span<const std::size_t> indices,
                                        uint8_t* out_root,
                                        uint8_t* out_hints) {
    const std::size_t layers = merkle_layers_for_size(num_leaves);
    const std::size_t num_nodes = (std::size_t{1} << (layers + 1)) - 1;
    std::vector<uint64_t> hint_nodes = merkle_hint_node_indices(num_leaves, indices);
    auto& pool = GpuPool::instance();
    uint8_t* d_leaves = pool.hashes(num_leaves * 32);
    uint8_t* d_nodes = pool.merkle(num_nodes * 32);
    uint64_t* d_hint_nodes = pool.input(hint_nodes.size());
    uint8_t* d_hints = pool.bytes(hint_nodes.size() * 32);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    ScopedCudaEvents ev;

    CUDA_CHECK(cudaEventRecord(ev.start()));
    if (num_leaves > 0) {
        CUDA_CHECK(cudaMemcpy(d_leaves, leaves, num_leaves * 32, cudaMemcpyHostToDevice));
    }
    if (!hint_nodes.empty()) {
        CUDA_CHECK(cudaMemcpy(d_hint_nodes, hint_nodes.data(),
                              hint_nodes.size() * sizeof(uint64_t), cudaMemcpyHostToDevice));
    }
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.h2d_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    gpu_sha256_merkle_tree_device(d_leaves, num_leaves, d_nodes);
    launch_gather_hashes(d_nodes, d_hint_nodes, d_hints, static_cast<uint32_t>(hint_nodes.size()));
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out_root, d_nodes + (num_nodes - 1) * 32, 32, cudaMemcpyDeviceToHost));
    if (!hint_nodes.empty()) {
        CUDA_CHECK(cudaMemcpy(out_hints, d_hints, hint_nodes.size() * 32, cudaMemcpyDeviceToHost));
    }
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
}

/// GPU 域元素编码: 每个 uint64_t (Montgomery) → 8 LE 字节
inline void gpu_encode_to_bytes(const uint64_t* values, uint8_t* out, std::size_t count) {
    auto& pool = GpuPool::instance();
    uint64_t* d_vals = pool.data(count);
    uint8_t*  d_out  = pool.bytes(count * 8);

    CUDA_CHECK(cudaMemcpy(d_vals, values, count * sizeof(uint64_t), cudaMemcpyHostToDevice));
    launch_encode_to_bytes(d_vals, d_out, static_cast<uint32_t>(count));
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(out, d_out, count * 8, cudaMemcpyDeviceToHost));
}

} // namespace whir::cuda
#endif // WHIR_CUDA
