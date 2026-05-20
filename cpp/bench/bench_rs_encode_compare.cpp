#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/mod_ntt.hpp"

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

struct CpuRow {
    double total_ms = 0.0;
};

struct GpuRow {
    double h2d_ms = 0.0;
    double kernel_ms = 0.0;
    double d2h_ms = 0.0;
    double total_ms = 0.0;
    double wall_ms = 0.0;
    bool available = false;
};

static std::vector<std::vector<Goldilocks>> make_coeffs(const Case& c) {
    Lcg rng(0x52535f434f4d50ULL ^ static_cast<uint64_t>(c.poly_size) ^
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

static CpuRow run_cpu(
    const std::vector<std::span<const Goldilocks>>& spans,
    const Case& c,
    std::vector<Goldilocks>& out) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    whir::cuda::set_gpu_dispatch_enabled(false);
#endif
    const auto t0 = std::chrono::steady_clock::now();
    out = whir::algebra::ntt::interleaved_rs_encode<Goldilocks>(
        engine, std::span<const std::span<const Goldilocks>>{spans},
        c.codeword_length, c.interleaving_depth);
    const auto t1 = std::chrono::steady_clock::now();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
    return {std::chrono::duration<double, std::milli>(t1 - t0).count()};
}

static GpuRow run_gpu(
    const std::vector<std::span<const Goldilocks>>& spans,
    const Case& c,
    std::vector<Goldilocks>& out) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    whir::cuda::set_gpu_dispatch_enabled(true);
    whir::cuda::set_gpu_ntt_threshold(0);
    const auto t0 = std::chrono::steady_clock::now();
    out = whir::algebra::ntt::interleaved_rs_encode<Goldilocks>(
        engine, std::span<const std::span<const Goldilocks>>{spans},
        c.codeword_length, c.interleaving_depth);
    const auto t1 = std::chrono::steady_clock::now();
    const auto timing = whir::cuda::last_ntt_timing();
    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
    return {timing.h2d_ms, timing.kernel_ms, timing.d2h_ms, timing.total_ms,
            std::chrono::duration<double, std::milli>(t1 - t0).count(), timing.used_gpu};
#else
    (void)spans;
    (void)c;
    (void)out;
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
            else if (arg == "--case" && i + 4 < argc) {
                cases.clear();
                Case c{};
                c.poly_size = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                c.codeword_length = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                c.interleaving_depth = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                c.num_polys = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
                cases.push_back(c);
            }
        }

        std::printf("poly_size,codeword_length,interleaving_depth,num_polys,total_elements,"
                    "cpu_ms,gpu_h2d_ms,gpu_kernel_ms,gpu_d2h_ms,gpu_total_ms,gpu_wall_ms,"
                    "speedup_kernel_only,speedup_end_to_end,correctness\n");

        for (const auto& c : cases) {
            double best_cpu = 1.0e300;
            GpuRow best_gpu{};
            bool correct = true;
            const auto coeffs = make_coeffs(c);
            const auto spans = make_spans(coeffs);

            for (int w = 0; w < std::max(warmups, 0); ++w) {
                std::vector<Goldilocks> ignored;
                (void)run_gpu(spans, c, ignored);
            }

            for (int r = 0; r < std::max(runs, 1); ++r) {
                std::vector<Goldilocks> cpu_out;
                std::vector<Goldilocks> gpu_out;
                const auto cpu = run_cpu(spans, c, cpu_out);
                const auto gpu = run_gpu(spans, c, gpu_out);
                best_cpu = std::min(best_cpu, cpu.total_ms);
                if (gpu.available && (!best_gpu.available || gpu.wall_ms < best_gpu.wall_ms)) {
                    best_gpu = gpu;
                }
                if (gpu.available && cpu_out != gpu_out) correct = false;
            }

            const std::size_t total_elements = c.codeword_length * c.interleaving_depth * c.num_polys;
            const double kernel_speedup =
                best_gpu.available && best_gpu.kernel_ms > 0.0 ? best_cpu / best_gpu.kernel_ms : 0.0;
            const double e2e_speedup =
                best_gpu.available && best_gpu.wall_ms > 0.0 ? best_cpu / best_gpu.wall_ms : 0.0;
            std::printf("%zu,%zu,%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%.3f,%s\n",
                        c.poly_size, c.codeword_length, c.interleaving_depth, c.num_polys,
                        total_elements, best_cpu, best_gpu.h2d_ms, best_gpu.kernel_ms,
                        best_gpu.d2h_ms, best_gpu.total_ms, best_gpu.wall_ms,
                        kernel_speedup, e2e_speedup,
                        best_gpu.available ? (correct ? "PASS" : "FAIL") : "GPU_UNAVAILABLE");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_rs_encode_compare error: %s\n", e.what());
        return 2;
    }
}
