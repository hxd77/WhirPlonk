// =============================================================================
// cuda_integration.hpp 鈥?CUDA 鍐呮牳鐨?C++ 闆嗘垚灞?
//
// 鎻愪緵涓?CPU NttEngine 鍏煎鐨勯珮灞?GPU 鎺ュ彛:
//   - gpu_ntt_batch()       鈫?鎵归噺 NTT (鏇夸唬 CPU ntt_dispatch)
//   - gpu_apply_twiddles()  鈫?Twiddle 鍥犲瓙涔樻硶
//   - gpu_transpose()       鈫?鐭╅樀杞疆
//   - gpu_encode_to_bytes() 鈫?鍩熷厓绱犵紪鐮?
//
// 鍐呴儴缁存姢涓€涓潤鎬?GPU 鍐呭瓨姹? 棣栨璋冪敤鏃跺垎閰? 鍚庣画澶嶇敤,
// 閬垮厤鍙嶅 cudaMalloc/cudaFree 鐨勫紑閿€銆?
//
// 浣跨敤鏂瑰紡 (鍦?NTT 寮曟搸涓?:
//   #ifdef WHIR_CUDA
//   if (size >= GPU_THRESHOLD) { gpu_ntt_batch(values, roots, size); return; }
//   #endif
//   // ... CPU 璺緞 ...
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

// GPU 鍔犻€熼槇鍊? 鍏冪礌鏁颁綆浜庢鍊肩洿鎺ヨ蛋 CPU (GPU 鍚姩寮€閿€ > 鏀剁泭)
static constexpr std::size_t GPU_NTT_THRESHOLD = 65536;   // 64K 鍏冪礌
static constexpr std::size_t GPU_TWIDDLE_THRESHOLD = 4096; // twiddle 璁＄畻杞? 闃堝€间綆

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
// GpuPool 鈥?鍗曚緥 GPU 鍐呭瓨姹? 澶嶇敤鏄惧瓨鍒嗛厤
//
// 绠＄悊涓夊潡缂撳啿鍖?
//   data_buf  鈥?NTT / twiddle / transpose 鐢ㄧ殑 uint64_t 鏁扮粍
//   roots_buf 鈥?鍗曚綅鏍硅〃 (涓婁紶涓€娆? 澶氭浣跨敤)
//   byte_buf  鈥?鍩熷厓绱犵紪鐮佽緭鍑?(uint8_t)
//
// 鎵€鏈?buffer 鎸夐渶鎵╁紶 (鍙涓嶅噺), 杩涚▼閫€鍑烘椂鑷姩閲婃斁.
// ===========================================================================
class GpuPool {
public:
    static GpuPool& instance() {
        static GpuPool pool;
        return pool;
    }

    /// 纭繚 data buffer 鈮?n 涓?uint64_t
    uint64_t* data(std::size_t n) {
        ensure_cap<uint64_t>(data_, data_cap_, n);
        return data_.get();
    }

    /// 纭繚 roots buffer 鈮?n 涓?uint64_t
    uint64_t* roots(std::size_t n) {
        ensure_cap<uint64_t>(roots_, roots_cap_, n);
        return roots_.get();
    }

    /// 纭繚 byte buffer 鈮?n 涓?uint8_t
    uint8_t* bytes(std::size_t n) {
        ensure_cap<uint8_t>(byte_, byte_cap_, n);
        return byte_.get();
    }

    /// 纭繚 hash output byte buffer 鈮?n 涓瓧鑺?
    uint8_t* hashes(std::size_t n) {
        ensure_cap<uint8_t>(hash_, hash_cap_, n);
        return hash_.get();
    }

    /// 纭繚 Merkle tree byte buffer 鈮?n 涓瓧鑺?
    uint8_t* merkle(std::size_t n) {
        ensure_cap<uint8_t>(merkle_, merkle_cap_, n);
        return merkle_.get();
    }

    uint8_t* pinned(std::size_t n) {
        ensure_host_cap(pinned_, pinned_cap_, n);
        return pinned_.get();
    }

    /// 纭繚杈撳叆 uint64_t buffer 鈮?n 涓厓绱?
    uint64_t* input(std::size_t n) {
        ensure_cap<uint64_t>(input_, input_cap_, n);
        return input_.get();
    }

    /// 纭繚涓存椂 uint64_t buffer 鈮?n 涓厓绱?
    uint64_t* temp(std::size_t n) {
        ensure_cap<uint64_t>(scratch_, scratch_cap_, n);
        return scratch_.get();
    }

    /// 涓婁紶鍗曚綅鏍硅〃鍒?GPU
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
    CudaPtr<uint8_t>  byte_;
    CudaPtr<uint8_t>  hash_;
    CudaPtr<uint8_t>  merkle_;
    HostPtr pinned_;
    std::size_t data_cap_ = 0, roots_cap_ = 0, scratch_cap_ = 0, input_cap_ = 0, byte_cap_ = 0, hash_cap_ = 0, merkle_cap_ = 0, roots_len_ = 0;
    std::size_t pinned_cap_ = 0;
    const uint64_t* roots_host_ = nullptr;
    double last_alloc_ms_ = 0.0;
};

// ===========================================================================
// 楂樺眰 GPU 鍑芥暟
// ===========================================================================

// ---- 鍐呴儴杈呭姪: sqrt_factor (鍚?CPU 绔? 鏈€澶?2 鐨勫箓鍥犲瓙 鈮?鈭歯) ----
inline std::size_t sqrt_factor_gpu(std::size_t n) {
    if (n <= 1) return 1;
    std::size_t r = 1;
    while (r * r * 4 <= n) r *= 2;
    return r;
}

// ---- 鍐呴儴: GPU NTT dispatch (鎵归噺瀛愬彉鎹? default stream 鑷姩淇濆簭) ----
// 杩斿洖鍊兼寚鍚戝寘鍚粨鏋滅殑缂撳啿鍖恒€傞€掑綊灞傚湪 d_data 涓?d_scratch 涔嬮棿 ping-pong锛?
// 閬垮厤 transpose 鍚庡啀鍋氭暣鍧?cudaMemcpyDeviceToDevice銆?
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

/// GPU 鎵归噺 NTT: 6-step Cooley-Tukey
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
    CUDA_CHECK(cudaDeviceSynchronize());  // 鍞竴鍚屾鐐? 绛夊緟鎵€鏈?kernel 瀹屾垚
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

/// GPU 鎵归噺 NTT 鍚庣珛鍗宠浆缃? 杈撳叆鎸?blocks脳ntt_size 鎺掑垪,
/// 杈撳嚭鎸?ntt_size脳blocks 琛屼富搴忔帓鍒?
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

/// GPU Reed-Solomon 缂栫爜: 绱у噾绯绘暟涓婁紶 鈫?GPU 闆跺～鍏?鎵撳寘 鈫?鎵归噺 NTT 鈫?鏈€缁堣浆缃?
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
    uint64_t* d_coeffs = pool.input(coeff_total);
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    uint8_t* d_hashes = pool.hashes(codeword_length * 32);
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
    launch_blake3_hash_goldilocks_rows(transposed, d_hashes, static_cast<uint32_t>(rows),
                                       static_cast<uint32_t>(codeword_length));
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out_matrix, transposed, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(out_hashes, d_hashes, codeword_length * 32, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_blake3_leaves_h2d", timing.h2d_ms);
    whir::profile::record("cuda", total, "gpu_blake3_leaves_kernel", timing.kernel_ms);
    whir::profile::record("cuda", total, "gpu_blake3_leaves_d2h", timing.d2h_ms);
    whir::profile::record("cuda", total, "gpu_blake3_leaves_total", timing.total_ms + timing.malloc_ms);
    return true;
}

/// GPU Reed-Solomon 缂栫爜骞剁洿鎺ヨ緭鍑?Goldilocks LE 瀛楄妭.
inline void gpu_interleaved_rs_encode_to_bytes(const uint64_t* coeffs, uint8_t* out,
                                               std::size_t num_polys,
                                               std::size_t poly_size,
                                               std::size_t codeword_length,
                                               std::size_t interleaving_depth) {
    auto& pool = GpuPool::instance();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t total = rows * codeword_length;
    uint64_t* d_coeffs = pool.input(coeff_total);
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    uint8_t* d_bytes = pool.bytes(total * 8);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
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
    launch_encode_to_bytes(transposed, d_bytes, static_cast<uint32_t>(total));
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out, d_bytes, total * 8, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
}

inline std::size_t merkle_layers_for_size(std::size_t size) noexcept;
inline void gpu_sha256_merkle_tree_device(const uint8_t* d_leaves,
                                          std::size_t num_leaves,
                                          uint8_t* d_nodes);
inline void gpu_blake3_merkle_tree_device(const uint8_t* d_leaves,
                                          std::size_t num_leaves,
                                          uint8_t* d_nodes,
                                          cudaStream_t stream = nullptr);

/// GPU Reed-Solomon 缂栫爜骞剁洿鎺ヨ緭鍑?SHA-256 leaf hashes.
inline void gpu_interleaved_rs_encode_sha256_leaves(const uint64_t* coeffs, uint8_t* out_hashes,
                                                    std::size_t num_polys,
                                                    std::size_t poly_size,
                                                    std::size_t codeword_length,
                                                    std::size_t interleaving_depth) {
    auto& pool = GpuPool::instance();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t total = rows * codeword_length;
    uint64_t* d_coeffs = pool.input(coeff_total);
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    uint8_t* d_bytes = nullptr;
    uint8_t* d_hashes = pool.hashes(codeword_length * 32);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
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
    if (codeword_length <= 65536) {
        launch_sha256_hash_goldilocks_rows(transposed, d_hashes, static_cast<uint32_t>(rows),
                                           static_cast<uint32_t>(codeword_length));
    } else {
        d_bytes = pool.bytes(total * 8);
        launch_encode_to_bytes(transposed, d_bytes, static_cast<uint32_t>(total));
        launch_sha256_hash_many(d_bytes, d_hashes, static_cast<uint32_t>(rows * sizeof(uint64_t)),
                                static_cast<uint32_t>(codeword_length));
    }
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out_hashes, d_hashes, codeword_length * 32, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
}

/// GPU Reed-Solomon 缂栫爜銆丼HA-256 leaf hash銆丼HA-256 Merkle root.
///
/// 鍙洖浼?32B Merkle root锛宭eaves 鍜屽唴閮ㄨ妭鐐瑰潎淇濈暀鍦?device 涓娿€?
inline void gpu_interleaved_rs_encode_sha256_merkle_root(const uint64_t* coeffs, uint8_t* out_root,
                                                         std::size_t num_polys,
                                                         std::size_t poly_size,
                                                         std::size_t codeword_length,
                                                         std::size_t interleaving_depth) {
    auto& pool = GpuPool::instance();
    const std::size_t coeff_total = num_polys * poly_size;
    const std::size_t rows = num_polys * interleaving_depth;
    const std::size_t total = rows * codeword_length;
    const std::size_t merkle_layers = merkle_layers_for_size(codeword_length);
    const std::size_t merkle_nodes = (std::size_t{1} << (merkle_layers + 1)) - 1;
    uint64_t* d_coeffs = pool.input(coeff_total);
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    uint8_t* d_hashes = pool.hashes(codeword_length * 32);
    uint8_t* d_merkle = pool.merkle(merkle_nodes * 32);
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
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
    if (codeword_length <= 65536) {
        launch_sha256_hash_goldilocks_rows(transposed, d_hashes, static_cast<uint32_t>(rows),
                                           static_cast<uint32_t>(codeword_length));
    } else {
        uint8_t* d_bytes = pool.bytes(total * 8);
        launch_encode_to_bytes(transposed, d_bytes, static_cast<uint32_t>(total));
        launch_sha256_hash_many(d_bytes, d_hashes, static_cast<uint32_t>(rows * sizeof(uint64_t)),
                                static_cast<uint32_t>(codeword_length));
    }
    gpu_sha256_merkle_tree_device(d_hashes, codeword_length, d_merkle);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start()));
    CUDA_CHECK(cudaMemcpy(out_root, d_merkle + (merkle_nodes - 1) * 32, 32, cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaEventRecord(ev.stop()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
}

/// GPU Reed-Solomon 编码、BLAKE3 leaves 和 BLAKE3 Merkle root.
///
/// 使用 pinned host staging、非阻塞 stream 和 async memcpy。该 root-only 路径只回传 32B root。
/// BLAKE3 device fast path 与 CPU Blake3::supports_size 对齐：每行消息为 64 的倍数且 <= 1024B。
inline bool gpu_interleaved_rs_encode_blake3_merkle_root_async(const uint64_t* coeffs, uint8_t* out_root,
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
    const std::size_t merkle_layers = merkle_layers_for_size(codeword_length);
    const std::size_t merkle_nodes = (std::size_t{1} << (merkle_layers + 1)) - 1;
    uint64_t* d_coeffs = pool.input(coeff_total);
    uint64_t* d_data = pool.data(total);
    uint64_t* d_scratch = pool.temp(total);
    uint8_t* d_hashes = pool.hashes(codeword_length * 32);
    uint8_t* d_merkle = pool.merkle(merkle_nodes * 32);
    uint8_t* pinned_coeffs = pool.pinned(coeff_total * sizeof(uint64_t));
    std::memcpy(pinned_coeffs, coeffs, coeff_total * sizeof(uint64_t));

    ScopedCudaStream stream;
    ScopedCudaEvents ev;
    auto& timing = last_ntt_timing_value();
    timing = {};
    timing.used_gpu = true;
    timing.malloc_ms = static_cast<float>(pool.last_alloc_ms());

    CUDA_CHECK(cudaEventRecord(ev.start(), stream.get()));
    CUDA_CHECK(cudaMemcpyAsync(d_coeffs, pinned_coeffs, coeff_total * sizeof(uint64_t),
                               cudaMemcpyHostToDevice, stream.get()));
    CUDA_CHECK(cudaEventRecord(ev.stop(), stream.get()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.h2d_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start(), stream.get()));
    CUDA_CHECK(cudaMemsetAsync(d_data, 0, total * sizeof(uint64_t), stream.get()));
    launch_pack_rs_coeffs(d_coeffs, d_data,
                          static_cast<uint32_t>(poly_size),
                          static_cast<uint32_t>(codeword_length),
                          static_cast<uint32_t>(interleaving_depth),
                          static_cast<uint32_t>(num_polys),
                          stream.get());
    uint64_t* result = gpu_ntt_dispatch(
        d_data, d_scratch, pool.roots(pool.roots_len()), pool.roots_len(), rows, codeword_length, stream.get());
    uint64_t* transposed = (result == d_data) ? d_scratch : d_data;
    launch_transpose(result, transposed, static_cast<uint32_t>(rows),
                     static_cast<uint32_t>(codeword_length), 1, stream.get());
    launch_blake3_hash_goldilocks_rows(transposed, d_hashes, static_cast<uint32_t>(rows),
                                       static_cast<uint32_t>(codeword_length), stream.get());
    gpu_blake3_merkle_tree_device(d_hashes, codeword_length, d_merkle, stream.get());
    CUDA_CHECK(cudaEventRecord(ev.stop(), stream.get()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.kernel_ms = elapsed_ms(ev.start(), ev.stop());

    CUDA_CHECK(cudaEventRecord(ev.start(), stream.get()));
    CUDA_CHECK(cudaMemcpyAsync(out_root, d_merkle + (merkle_nodes - 1) * 32, 32,
                               cudaMemcpyDeviceToHost, stream.get()));
    CUDA_CHECK(cudaEventRecord(ev.stop(), stream.get()));
    CUDA_CHECK(cudaEventSynchronize(ev.stop()));
    timing.d2h_ms = elapsed_ms(ev.start(), ev.stop());
    timing.total_ms = timing.h2d_ms + timing.kernel_ms + timing.d2h_ms;
    whir::profile::record("cuda", total, "gpu_blake3_root_h2d", timing.h2d_ms);
    whir::profile::record("cuda", total, "gpu_blake3_root_kernel", timing.kernel_ms);
    whir::profile::record("cuda", total, "gpu_blake3_root_d2h", timing.d2h_ms);
    whir::profile::record("cuda", total, "gpu_blake3_root_total", timing.total_ms + timing.malloc_ms);
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
/// 杈撳叆 leaves 涓?num_leaves 涓?32B hash銆傝澶囩琛ラ綈闆?hash 鍚庨€愬眰鎵ц
/// parent = SHA256(left || right)銆傚鏋?out_nodes 闈炵┖锛屽洖浼犲畬鏁?witness nodes锛?
/// 鍚﹀垯鍙洖浼?root銆?
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
/// 鏋勫缓 device Merkle tree锛屼絾鍙洖浼?root 鍜屾寜 CPU open_path 椤哄簭鎺掑垪鐨?sibling hints銆?
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

/// GPU 鍩熷厓绱犵紪鐮? 姣忎釜 uint64_t (Montgomery) 鈫?8 LE 瀛楄妭
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
