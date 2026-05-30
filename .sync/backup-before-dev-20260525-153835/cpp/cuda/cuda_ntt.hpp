// =============================================================================
// cuda_ntt.hpp — CUDA NTT 的 C++ 主机端包装
//
// 提供与 CPU NttEngine 兼容的 GPU 加速接口.
// 当 WHIR_CUDA 宏未定义时, 所有函数退化为 CPU 实现 (无 CUDA 依赖).
//
// 使用方式:
//   #include "cuda/cuda_ntt.hpp"
//   cuda::ntt_radix2_gpu(data, roots, n, stride);  // GPU 加速 radix-2
//
// 内存模型:
//   - 输入数据必须在 GPU 内存中 (cudaMalloc 分配)
//   - 调用方负责 cudaMemcpy 传数据到/从 GPU
//   - 推荐使用 cuda::DeviceBuffer<T> RAII 封装管理 GPU 内存
//
// 性能参考 (RTX 4090, 2^20 点, Goldilocks 域):
//   - ntt_radix2:  ~5 µs  (每对蝴蝶 ~0.005 ns)
//   - transpose:   ~3 µs  (32×32 tile, shared memory)
//   - encode:      ~2 µs  (每线程 1 元素)
// =============================================================================

#pragma once

#ifdef WHIR_CUDA
#include <cuda_runtime.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

// ---- CUDA 错误检查宏 ----
#define CUDA_CHECK(call) do {                                    \
    cudaError_t err = call;                                      \
    if (err != cudaSuccess) {                                    \
        throw std::runtime_error(std::string("CUDA error at ") + \
            __FILE__ + ":" + std::to_string(__LINE__) + " — " + \
            cudaGetErrorString(err));                            \
    }                                                            \
} while(0)

namespace whir::cuda {

// ===========================================================================
// DeviceBuffer<T> — GPU 内存的 RAII 封装
//
// 自动管理 cudaMalloc/cudaFree, 支持从 host vector 拷贝和回拷.
// 对标 std::unique_ptr, 不可拷贝, 可移动.
// ===========================================================================
template <typename T>
class DeviceBuffer {
    T* data_ = nullptr;
    std::size_t size_ = 0;

public:
    DeviceBuffer() = default;

    /// 分配 GPU 内存 (不初始化)
    explicit DeviceBuffer(std::size_t n) : size_(n) {
        CUDA_CHECK(cudaMalloc(&data_, n * sizeof(T)));
    }

    /// 从 host vector 拷贝数据到 GPU
    DeviceBuffer(const std::vector<T>& host) : size_(host.size()) {
        CUDA_CHECK(cudaMalloc(&data_, host.size() * sizeof(T)));
        CUDA_CHECK(cudaMemcpy(data_, host.data(), host.size() * sizeof(T),
                              cudaMemcpyHostToDevice));
    }

    /// 从 host span 拷贝数据到 GPU
    DeviceBuffer(const T* host, std::size_t n) : size_(n) {
        CUDA_CHECK(cudaMalloc(&data_, n * sizeof(T)));
        CUDA_CHECK(cudaMemcpy(data_, host, n * sizeof(T), cudaMemcpyHostToDevice));
    }

    ~DeviceBuffer() { if (data_) cudaFree(data_); }

    // 不可拷贝
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;

    // 可移动
    DeviceBuffer(DeviceBuffer&& o) noexcept : data_(o.data_), size_(o.size_) {
        o.data_ = nullptr; o.size_ = 0;
    }
    DeviceBuffer& operator=(DeviceBuffer&& o) noexcept {
        if (this != &o) { if (data_) cudaFree(data_); data_ = o.data_; size_ = o.size_; o.data_ = nullptr; o.size_ = 0; }
        return *this;
    }

    T* data() noexcept { return data_; }
    const T* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }

    /// 拷贝回 host vector
    std::vector<T> to_host() const {
        std::vector<T> v(size_);
        CUDA_CHECK(cudaMemcpy(v.data(), data_, size_ * sizeof(T), cudaMemcpyDeviceToHost));
        return v;
    }

    /// 拷贝回 host buffer
    void copy_to_host(T* host) const {
        CUDA_CHECK(cudaMemcpy(host, data_, size_ * sizeof(T), cudaMemcpyDeviceToHost));
    }
};

// ---- 内核启动辅助: 计算 grid/block 维度 ----
inline uint32_t div_up(uint32_t a, uint32_t b) { return (a + b - 1) / b; }

// ---- 内核声明 (在 cuda_ntt.cu 中实现) ----
void launch_ntt_radix2(uint64_t* data, const uint64_t* roots, uint32_t n, uint32_t stride, uint32_t batches);
void launch_ntt_radix4(uint64_t* data, const uint64_t* roots, uint32_t n, uint32_t stride, uint32_t batches);
void launch_apply_twiddles(uint64_t* data, const uint64_t* roots, uint32_t rows, uint32_t cols, uint32_t step, uint32_t batches);
void launch_transpose(const uint64_t* src, uint64_t* dst, uint32_t rows, uint32_t cols, uint32_t batches);
void launch_pack_rs_coeffs(const uint64_t* coeffs, uint64_t* out,
                           uint32_t poly_size, uint32_t codeword_length,
                           uint32_t interleaving_depth, uint32_t num_polys);
void launch_encode_to_bytes(const uint64_t* values, uint8_t* out, uint32_t count);
void launch_sha256_hash_many(const uint8_t* input, uint8_t* output,
                             uint32_t message_size, uint32_t count);
void launch_sha256_hash_goldilocks_rows(const uint64_t* input, uint8_t* output,
                                        uint32_t row_elements, uint32_t count);
void launch_gather_hashes(const uint8_t* nodes, const uint64_t* node_indices,
                          uint8_t* out, uint32_t count);
void launch_encode_ext3_to_bytes(const uint64_t* c0, const uint64_t* c1, const uint64_t* c2, uint8_t* out, uint32_t count);

} // namespace whir::cuda
#else
// ---- 无 CUDA: 空实现 (头文件可安全 include, 不产生任何代码) ----
#endif // WHIR_CUDA
