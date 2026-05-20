#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"

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

struct CpuTiming {
    double ms = 0.0;
};

struct GpuTimingRow {
    double h2d_ms = 0.0;
    double kernel_ms = 0.0;
    double d2h_ms = 0.0;
    double total_ms = 0.0;
    bool available = false;
};

static std::vector<Goldilocks> make_input(std::size_t n) {
    Lcg rng(0x4e54545f434f4d50ULL ^ static_cast<uint64_t>(n));
    std::vector<Goldilocks> values(n);
    for (auto& v : values) v = Goldilocks::from_u64(rng.next());
    return values;
}

static CpuTiming run_cpu(std::vector<Goldilocks>& values, std::size_t n) {
    auto& engine = whir::algebra::ntt::goldilocks_engine();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    whir::cuda::set_gpu_dispatch_enabled(false);
#endif
    const auto t0 = std::chrono::steady_clock::now();
    engine.ntt_batch(std::span<Goldilocks>{values}, n);
    const auto t1 = std::chrono::steady_clock::now();
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
    return {std::chrono::duration<double, std::milli>(t1 - t0).count()};
}

static GpuTimingRow run_gpu(std::vector<Goldilocks>& values, std::size_t n) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    auto& engine = whir::algebra::ntt::goldilocks_engine();
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    whir::cuda::set_gpu_dispatch_enabled(true);
    whir::cuda::set_gpu_ntt_threshold(0);
    engine.ntt_batch(std::span<Goldilocks>{values}, n);
    const auto timing = whir::cuda::last_ntt_timing();
    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
    return {timing.h2d_ms, timing.kernel_ms, timing.d2h_ms, timing.total_ms, timing.used_gpu};
#else
    (void)values;
    (void)n;
    return {};
#endif
}

int main(int argc, char** argv) {
    try {
        std::vector<std::size_t> sizes = {
            std::size_t{1} << 10,
            std::size_t{1} << 12,
            std::size_t{1} << 16,
            std::size_t{1} << 20,
            std::size_t{1} << 24,
        };
        int runs = 3;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--runs" && i + 1 < argc) runs = std::atoi(argv[++i]);
            else if (arg == "--sizes") {
                sizes.clear();
                while (i + 1 < argc && argv[i + 1][0] != '-') {
                    sizes.push_back(static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10)));
                }
            }
        }

        std::printf("input_size,cpu_ms,gpu_h2d_ms,gpu_kernel_ms,gpu_d2h_ms,gpu_total_ms,"
                    "speedup_kernel_only,speedup_end_to_end,correctness\n");

        for (std::size_t n : sizes) {
            double best_cpu = 1.0e300;
            GpuTimingRow best_gpu{};
            bool correct = true;

            for (int r = 0; r < std::max(runs, 1); ++r) {
                auto cpu_values = make_input(n);
                auto gpu_values = cpu_values;

                const auto cpu = run_cpu(cpu_values, n);
                best_cpu = std::min(best_cpu, cpu.ms);

                const auto gpu = run_gpu(gpu_values, n);
                if (gpu.available &&
                    (!best_gpu.available || gpu.total_ms < best_gpu.total_ms)) {
                    best_gpu = gpu;
                }
                if (gpu.available && cpu_values != gpu_values) {
                    correct = false;
                }
            }

            const double kernel_speedup =
                best_gpu.available && best_gpu.kernel_ms > 0.0 ? best_cpu / best_gpu.kernel_ms : 0.0;
            const double e2e_speedup =
                best_gpu.available && best_gpu.total_ms > 0.0 ? best_cpu / best_gpu.total_ms : 0.0;

            std::printf("%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%.3f,%s\n",
                        n, best_cpu, best_gpu.h2d_ms, best_gpu.kernel_ms,
                        best_gpu.d2h_ms, best_gpu.total_ms,
                        kernel_speedup, e2e_speedup,
                        best_gpu.available ? (correct ? "PASS" : "FAIL") : "GPU_UNAVAILABLE");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_ntt_compare error: %s\n", e.what());
        return 2;
    }
}
