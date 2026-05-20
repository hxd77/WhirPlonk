#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/mod_ntt.hpp"
#include "whir/protocols/matrix_commit.hpp"

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

struct Case {
    std::size_t poly_size;
    std::size_t codeword_length;
    std::size_t interleaving_depth;
    std::size_t num_polys;
};

bool has_cuda_device() {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    int count = 0;
    const cudaError_t err = cudaGetDeviceCount(&count);
    return err == cudaSuccess && count > 0;
#else
    return false;
#endif
}

std::vector<std::vector<Goldilocks>> make_coeffs(const Case& c) {
    Lcg rng(0x425954455f5253ULL ^ static_cast<uint64_t>(c.poly_size) ^
            (static_cast<uint64_t>(c.codeword_length) << 16) ^
            (static_cast<uint64_t>(c.interleaving_depth) << 32) ^
            (static_cast<uint64_t>(c.num_polys) << 48));
    std::vector<std::vector<Goldilocks>> coeffs(c.num_polys);
    for (auto& poly : coeffs) {
        poly.resize(c.poly_size);
        for (auto& v : poly) v = Goldilocks::from_u64(rng.next());
    }
    return coeffs;
}

std::vector<std::span<const Goldilocks>> make_spans(
    const std::vector<std::vector<Goldilocks>>& coeffs) {
    std::vector<std::span<const Goldilocks>> spans;
    spans.reserve(coeffs.size());
    for (const auto& poly : coeffs) spans.emplace_back(poly);
    return spans;
}

std::vector<std::uint8_t> encode_cpu_bytes(
    const std::vector<std::span<const Goldilocks>>& spans,
    const Case& c) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    whir::cuda::set_gpu_dispatch_enabled(false);
#endif
    const auto encoded = whir::algebra::ntt::interleaved_rs_encode<Goldilocks>(
        engine, std::span<const std::span<const Goldilocks>>{spans},
        c.codeword_length, c.interleaving_depth);
    std::vector<std::uint8_t> out(encoded.size() * sizeof(uint64_t));
    whir::protocols::matrix_commit::encode_into<Goldilocks>(
        std::span<const Goldilocks>{encoded}, std::span<std::uint8_t>{out});
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
    return out;
}

std::vector<std::uint8_t> encode_gpu_bytes(
    const std::vector<std::span<const Goldilocks>>& spans,
    const Case& c) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    whir::cuda::set_gpu_dispatch_enabled(true);
    whir::cuda::set_gpu_ntt_threshold(0);
    std::vector<std::uint8_t> out;
    const bool ok = engine.try_gpu_interleaved_rs_encode_to_bytes(
        std::span<const std::span<const Goldilocks>>{spans},
        c.codeword_length, c.interleaving_depth, out);
    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
    EXPECT_TRUE(ok);
    return out;
#else
    (void)spans;
    (void)c;
    return {};
#endif
}

} // namespace

TEST(CudaRsEncodeBytes, MatchesCpuBytes) {
    if (!has_cuda_device()) GTEST_SKIP() << "CUDA device unavailable";

    for (const Case c : {
             Case{64, 256, 1, 1},
             Case{256, 1024, 4, 2},
             Case{1024, 4096, 4, 4},
             Case{4096, 16384, 4, 4},
             Case{65536, 262144, 4, 4},
         }) {
        const auto coeffs = make_coeffs(c);
        const auto spans = make_spans(coeffs);
        EXPECT_EQ(encode_cpu_bytes(spans, c), encode_gpu_bytes(spans, c));
    }
}
