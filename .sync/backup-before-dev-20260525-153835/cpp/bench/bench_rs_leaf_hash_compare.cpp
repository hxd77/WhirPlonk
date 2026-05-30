#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/mod_ntt.hpp"
#include "whir/hash/blake3_engine.hpp"
#include "whir/hash/hash_engine.hpp"
#include "whir/protocols/matrix_commit.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <span>
#include <string>
#include <vector>

using whir::algebra::Goldilocks;
using whir::hash::Hash;

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

struct GpuRow {
    double h2d_ms = 0.0;
    double kernel_ms = 0.0;
    double d2h_ms = 0.0;
    double gpu_total_ms = 0.0;
    double bytes_wall_ms = 0.0;
    double hash_ms = 0.0;
    double wall_ms = 0.0;
    bool available = false;
};

static std::vector<std::vector<Goldilocks>> make_coeffs(const Case& c) {
    Lcg rng(0x4c4541465f5253ULL ^ static_cast<uint64_t>(c.poly_size) ^
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

static std::vector<std::span<const Goldilocks>> make_spans(
    const std::vector<std::vector<Goldilocks>>& coeffs) {
    std::vector<std::span<const Goldilocks>> spans;
    spans.reserve(coeffs.size());
    for (const auto& poly : coeffs) spans.emplace_back(poly);
    return spans;
}

static double run_cpu(
    const whir::hash::HashEngine& hash_engine,
    const std::vector<std::span<const Goldilocks>>& spans,
    const Case& c,
    std::vector<Hash>& leaves) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    whir::cuda::set_gpu_dispatch_enabled(false);
#endif
    const auto t0 = std::chrono::steady_clock::now();
    const auto matrix = whir::algebra::ntt::interleaved_rs_encode<Goldilocks>(
        engine, std::span<const std::span<const Goldilocks>>{spans},
        c.codeword_length, c.interleaving_depth);
    leaves.resize(c.codeword_length);
    whir::protocols::matrix_commit::commit_leaves<Goldilocks>(
        hash_engine, std::span<const Goldilocks>{matrix}, c.num_polys * c.interleaving_depth,
        std::span<Hash>{leaves});
    const auto t1 = std::chrono::steady_clock::now();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

static GpuRow run_gpu_bytes_then_cpu_hash(
    const whir::hash::HashEngine& hash_engine,
    const std::vector<std::span<const Goldilocks>>& spans,
    const Case& c,
    std::vector<Hash>& leaves) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    whir::cuda::set_gpu_dispatch_enabled(true);
    whir::cuda::set_gpu_ntt_threshold(0);

    std::vector<std::uint8_t> bytes;
    const auto t0 = std::chrono::steady_clock::now();
    const auto bytes_t0 = t0;
    const bool ok = engine.try_gpu_interleaved_rs_encode_to_bytes(
        std::span<const std::span<const Goldilocks>>{spans},
        c.codeword_length, c.interleaving_depth, bytes);
    const auto bytes_t1 = std::chrono::steady_clock::now();
    const auto timing = whir::cuda::last_ntt_timing();

    const std::size_t num_cols = c.num_polys * c.interleaving_depth;
    const std::size_t message_size = num_cols * sizeof(uint64_t);
    leaves.resize(c.codeword_length);
    const auto hash_t0 = std::chrono::steady_clock::now();
    hash_engine.hash_many(message_size, std::span<const std::uint8_t>{bytes}, std::span<Hash>{leaves});
    const auto hash_t1 = std::chrono::steady_clock::now();
    const auto t1 = hash_t1;

    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
    return {timing.h2d_ms, timing.kernel_ms, timing.d2h_ms, timing.total_ms,
            std::chrono::duration<double, std::milli>(bytes_t1 - bytes_t0).count(),
            std::chrono::duration<double, std::milli>(hash_t1 - hash_t0).count(),
            std::chrono::duration<double, std::milli>(t1 - t0).count(),
            ok && timing.used_gpu};
#else
    (void)hash_engine;
    (void)spans;
    (void)c;
    (void)leaves;
    return {};
#endif
}

int main(int argc, char** argv) {
    try {
        int runs = 3;
        int warmups = 1;
        std::vector<Case> cases = {
            {std::size_t{1} << 12, std::size_t{1} << 14, 4, 4},
            {std::size_t{1} << 14, std::size_t{1} << 16, 4, 4},
            {std::size_t{1} << 16, std::size_t{1} << 18, 4, 4},
            {std::size_t{1} << 18, std::size_t{1} << 20, 4, 4},
        };

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--runs" && i + 1 < argc) runs = std::atoi(argv[++i]);
            else if (arg == "--warmups" && i + 1 < argc) warmups = std::atoi(argv[++i]);
        }

        whir::hash::Blake3 hash_engine;
        std::printf("poly_size,codeword_length,interleaving_depth,num_polys,num_leaves,message_size,"
                    "cpu_ms,gpu_h2d_ms,gpu_kernel_ms,gpu_d2h_ms,gpu_bytes_wall_ms,cpu_hash_ms,"
                    "gpu_wall_ms,speedup_end_to_end,correctness\n");

        for (const auto& c : cases) {
            const auto coeffs = make_coeffs(c);
            const auto spans = make_spans(coeffs);
            for (int w = 0; w < std::max(warmups, 0); ++w) {
                std::vector<Hash> ignored;
                (void)run_gpu_bytes_then_cpu_hash(hash_engine, spans, c, ignored);
            }

            double best_cpu = 1.0e300;
            GpuRow best_gpu{};
            bool correct = true;
            for (int r = 0; r < std::max(runs, 1); ++r) {
                std::vector<Hash> cpu_leaves;
                std::vector<Hash> gpu_leaves;
                best_cpu = std::min(best_cpu, run_cpu(hash_engine, spans, c, cpu_leaves));
                const auto gpu = run_gpu_bytes_then_cpu_hash(hash_engine, spans, c, gpu_leaves);
                if (gpu.available && (!best_gpu.available || gpu.wall_ms < best_gpu.wall_ms)) {
                    best_gpu = gpu;
                }
                if (gpu.available && cpu_leaves != gpu_leaves) correct = false;
            }

            const std::size_t num_cols = c.num_polys * c.interleaving_depth;
            const std::size_t message_size = num_cols * sizeof(uint64_t);
            const double speedup =
                best_gpu.available && best_gpu.wall_ms > 0.0 ? best_cpu / best_gpu.wall_ms : 0.0;
            std::printf("%zu,%zu,%zu,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%s\n",
                        c.poly_size, c.codeword_length, c.interleaving_depth, c.num_polys,
                        c.codeword_length, message_size, best_cpu, best_gpu.h2d_ms,
                        best_gpu.kernel_ms, best_gpu.d2h_ms, best_gpu.bytes_wall_ms,
                        best_gpu.hash_ms, best_gpu.wall_ms, speedup,
                        best_gpu.available ? (correct ? "PASS" : "FAIL") : "GPU_UNAVAILABLE");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_rs_leaf_hash_compare error: %s\n", e.what());
        return 2;
    }
}
