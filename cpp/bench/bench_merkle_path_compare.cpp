#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/merkle_tree.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <span>
#include <string>
#include <vector>

#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
#include "cuda/cuda_integration.hpp"
#endif

using whir::hash::Hash;

struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

struct CpuRow {
    double ms = 0.0;
    Hash root{};
    std::vector<Hash> hints;
};

struct GpuRow {
    double h2d_ms = 0.0;
    double kernel_ms = 0.0;
    double d2h_ms = 0.0;
    double total_ms = 0.0;
    double wall_ms = 0.0;
    Hash root{};
    std::vector<Hash> hints;
    bool available = false;
};

static std::vector<Hash> make_leaves(std::size_t n) {
    Lcg rng(0x4d45524b50424e43ULL ^ static_cast<uint64_t>(n));
    std::vector<Hash> leaves(n);
    for (auto& h : leaves) {
        for (auto& b : h) b = static_cast<std::uint8_t>(rng.next() >> 56);
    }
    return leaves;
}

static std::vector<std::size_t> make_indices(std::size_t n, std::size_t query_count) {
    std::vector<std::size_t> indices;
    indices.reserve(query_count);
    Lcg rng(0x5155455259494458ULL ^ static_cast<uint64_t>(n) ^
            (static_cast<uint64_t>(query_count) << 32));
    for (std::size_t i = 0; i < query_count; ++i) {
        indices.push_back(static_cast<std::size_t>(rng.next() % n));
    }
    if (query_count > 0) {
        indices[0] = 0;
        indices.back() = n - 1;
    }
    return indices;
}

static CpuRow run_cpu(const std::vector<Hash>& leaves, const std::vector<std::size_t>& indices) {
    whir::hash::Sha2 sha2;
    const auto config = whir::protocols::merkle_tree::make_config(
        whir::hash::ENGINE_ID_SHA2, leaves.size());
    const auto t0 = std::chrono::steady_clock::now();
    auto witness = whir::protocols::merkle_tree::build_tree(
        config, leaves,
        [&](const whir::EngineId&) -> const whir::hash::HashEngine& { return sha2; });
    auto hints = whir::protocols::merkle_tree::open_path(
        config, witness, std::span<const std::size_t>{indices});
    const auto t1 = std::chrono::steady_clock::now();
    return {std::chrono::duration<double, std::milli>(t1 - t0).count(),
            witness.nodes.back(), std::move(hints)};
}

static GpuRow run_gpu(const std::vector<Hash>& leaves, const std::vector<std::size_t>& indices) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    GpuRow row;
    const auto hint_nodes = whir::cuda::merkle_hint_node_indices(
        leaves.size(), std::span<const std::size_t>{indices});
    row.hints.resize(hint_nodes.size());
    const auto t0 = std::chrono::steady_clock::now();
    whir::cuda::gpu_sha256_merkle_open_path(
        reinterpret_cast<const std::uint8_t*>(leaves.data()),
        leaves.size(), std::span<const std::size_t>{indices}, row.root.data(),
        reinterpret_cast<std::uint8_t*>(row.hints.data()));
    const auto t1 = std::chrono::steady_clock::now();
    const auto timing = whir::cuda::last_ntt_timing();
    row.h2d_ms = timing.h2d_ms;
    row.kernel_ms = timing.kernel_ms;
    row.d2h_ms = timing.d2h_ms;
    row.total_ms = timing.total_ms;
    row.wall_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    row.available = timing.used_gpu;
    return row;
#else
    (void)leaves;
    (void)indices;
    return {};
#endif
}

int main(int argc, char** argv) {
    try {
        int runs = 3;
        int warmups = 1;
        std::size_t query_count = 32;
        std::vector<std::size_t> sizes = {
            std::size_t{1} << 10,
            std::size_t{1} << 12,
            std::size_t{1} << 16,
            std::size_t{1} << 20,
        };

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--runs" && i + 1 < argc) runs = std::atoi(argv[++i]);
            else if (arg == "--warmups" && i + 1 < argc) warmups = std::atoi(argv[++i]);
            else if (arg == "--queries" && i + 1 < argc) query_count = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
        }

        std::printf("num_leaves,query_count,hint_count,cpu_ms,gpu_h2d_ms,gpu_kernel_ms,"
                    "gpu_d2h_ms,gpu_wall_ms,speedup_end_to_end,correctness\n");

        for (std::size_t n : sizes) {
            const auto leaves = make_leaves(n);
            const auto indices = make_indices(n, query_count);
            for (int w = 0; w < std::max(warmups, 0); ++w) {
                (void)run_gpu(leaves, indices);
            }

            CpuRow best_cpu;
            best_cpu.ms = 1.0e300;
            GpuRow best_gpu;
            bool correct = true;
            for (int r = 0; r < std::max(runs, 1); ++r) {
                auto cpu = run_cpu(leaves, indices);
                if (cpu.ms < best_cpu.ms) best_cpu = std::move(cpu);
                auto gpu = run_gpu(leaves, indices);
                if (gpu.available && (gpu.root != best_cpu.root || gpu.hints != best_cpu.hints)) {
                    correct = false;
                }
                if (gpu.available && (!best_gpu.available || gpu.wall_ms < best_gpu.wall_ms)) {
                    best_gpu = std::move(gpu);
                }
            }

            const double speedup =
                best_gpu.available && best_gpu.wall_ms > 0.0 ? best_cpu.ms / best_gpu.wall_ms : 0.0;
            std::printf("%zu,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%s\n",
                        n, indices.size(), best_cpu.hints.size(), best_cpu.ms,
                        best_gpu.h2d_ms, best_gpu.kernel_ms, best_gpu.d2h_ms,
                        best_gpu.wall_ms, speedup,
                        best_gpu.available ? (correct ? "PASS" : "FAIL") : "GPU_UNAVAILABLE");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_merkle_path_compare error: %s\n", e.what());
        return 2;
    }
}
