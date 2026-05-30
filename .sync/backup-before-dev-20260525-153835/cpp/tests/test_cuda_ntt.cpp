#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"

#include <cstdint>
#include <span>
#include <vector>

#include <gtest/gtest.h>

#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
#include <cuda_runtime.h>
#endif

using whir::algebra::Goldilocks;

namespace {

struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

std::vector<Goldilocks> make_input(std::size_t n, std::size_t batch) {
    Lcg rng(0x435544415f4e5454ULL ^ static_cast<uint64_t>(n) ^
            (static_cast<uint64_t>(batch) << 32));
    std::vector<Goldilocks> values(n * batch);
    for (auto& v : values) v = Goldilocks::from_u64(rng.next());
    return values;
}

void run_cpu_ntt(std::vector<Goldilocks>& values, std::size_t n) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    whir::cuda::set_gpu_dispatch_enabled(false);
#endif
    engine.ntt_batch(std::span<Goldilocks>{values}, n);
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
}

bool has_cuda_device() {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    int count = 0;
    const cudaError_t err = cudaGetDeviceCount(&count);
    return err == cudaSuccess && count > 0;
#else
    return false;
#endif
}

void run_gpu_ntt(std::vector<Goldilocks>& values, std::size_t n) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    whir::cuda::set_gpu_dispatch_enabled(true);
    whir::cuda::set_gpu_ntt_threshold(0);
    engine.ntt_batch(std::span<Goldilocks>{values}, n);
    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#else
    (void)values;
    (void)n;
#endif
}

} // namespace

TEST(CudaNtt, MatchesCpuForRandomGoldilocksInputs) {
    if (!has_cuda_device()) GTEST_SKIP() << "CUDA device unavailable";

    for (std::size_t n : {2ULL, 4ULL, 8ULL, 16ULL, 1024ULL, 4096ULL, 65536ULL}) {
        for (std::size_t batch : {1ULL, 3ULL}) {
            auto cpu = make_input(n, batch);
            auto gpu = cpu;
            run_cpu_ntt(cpu, n);
            run_gpu_ntt(gpu, n);
            ASSERT_EQ(cpu, gpu) << "n=" << n << " batch=" << batch;
        }
    }
}

TEST(CudaNtt, MatchesCpuForSpecialValues) {
    if (!has_cuda_device()) GTEST_SKIP() << "CUDA device unavailable";

    constexpr uint64_t p = Goldilocks::MODULUS;
    std::vector<Goldilocks> cpu = {
        Goldilocks::zero(),
        Goldilocks::one(),
        Goldilocks::from_u64(p - 1),
        Goldilocks::from_u64(p - 2),
        Goldilocks::from_u64(0xFFFFFFFFULL),
        Goldilocks::from_u64(0x100000000ULL),
        Goldilocks::from_u64(0xFFFFFFFFFFFFFFFFULL),
        Goldilocks::from_u64(7),
    };
    auto gpu = cpu;
    run_cpu_ntt(cpu, cpu.size());
    run_gpu_ntt(gpu, gpu.size());
    EXPECT_EQ(cpu, gpu);
}
