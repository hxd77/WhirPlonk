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
    std::vector<Hash> nodes;
};

struct GpuRow {
    double h2d_ms = 0.0;
    double kernel_ms = 0.0;
    double d2h_ms = 0.0;
    double total_ms = 0.0;
    double wall_ms = 0.0;
    Hash root{};
    std::vector<Hash> nodes;
    bool available = false;
};

static std::vector<Hash> make_leaves(std::size_t n) {
    Lcg rng(0x4d45524b42454e43ULL ^ static_cast<uint64_t>(n));
    std::vector<Hash> leaves(n);
    for (auto& h : leaves) {
        for (auto& b : h) b = static_cast<std::uint8_t>(rng.next() >> 56);
    }
    return leaves;
}

static CpuRow run_cpu(const std::vector<Hash>& leaves) {
    whir::hash::Sha2 sha2;
    const auto config = whir::protocols::merkle_tree::make_config(
        whir::hash::ENGINE_ID_SHA2, leaves.size());
    const auto t0 = std::chrono::steady_clock::now();
    auto witness = whir::protocols::merkle_tree::build_tree(
        config, leaves,
        [&](const whir::EngineId&) -> const whir::hash::HashEngine& { return sha2; });
    const auto t1 = std::chrono::steady_clock::now();
    CpuRow row;
    row.ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    row.nodes = std::move(witness.nodes);
    row.root = row.nodes.back();
    return row;
}

static GpuRow run_gpu(const std::vector<Hash>& leaves, bool full_witness) {
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    GpuRow row;
    const std::size_t layers = whir::cuda::merkle_layers_for_size(leaves.size());
    const std::size_t num_nodes = (std::size_t{1} << (layers + 1)) - 1;
    if (full_witness) row.nodes.resize(num_nodes);
    const auto t0 = std::chrono::steady_clock::now();
    whir::cuda::gpu_sha256_merkle_tree(
        reinterpret_cast<const std::uint8_t*>(leaves.data()),
        leaves.size(), row.root.data(),
        full_witness ? reinterpret_cast<std::uint8_t*>(row.nodes.data()) : nullptr);
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
    (void)full_witness;
    return {};
#endif
}

int main(int argc, char** argv) {
    try {
        int runs = 3;
        int warmups = 1;
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
        }

        std::printf("num_leaves,num_nodes,cpu_ms,gpu_root_h2d_ms,gpu_root_kernel_ms,"
                    "gpu_root_d2h_ms,gpu_root_wall_ms,gpu_witness_wall_ms,"
                    "speedup_root_end_to_end,speedup_witness_end_to_end,correctness\n");

        for (std::size_t n : sizes) {
            const auto leaves = make_leaves(n);
            for (int w = 0; w < std::max(warmups, 0); ++w) {
                (void)run_gpu(leaves, false);
                (void)run_gpu(leaves, true);
            }

            CpuRow best_cpu;
            best_cpu.ms = 1.0e300;
            GpuRow best_root;
            GpuRow best_witness;
            bool correct = true;

            for (int r = 0; r < std::max(runs, 1); ++r) {
                auto cpu = run_cpu(leaves);
                if (cpu.ms < best_cpu.ms) best_cpu = std::move(cpu);

                auto gpu_root = run_gpu(leaves, false);
                if (gpu_root.available && gpu_root.root != best_cpu.root) correct = false;

                auto gpu_witness = run_gpu(leaves, true);
                if (gpu_witness.available && gpu_witness.nodes != best_cpu.nodes) correct = false;

                if (gpu_root.available && (!best_root.available || gpu_root.wall_ms < best_root.wall_ms)) {
                    best_root = std::move(gpu_root);
                }
                if (gpu_witness.available &&
                    (!best_witness.available || gpu_witness.wall_ms < best_witness.wall_ms)) {
                    best_witness = std::move(gpu_witness);
                }
            }

            const std::size_t layers = whir::protocols::merkle_tree::layers_for_size(n);
            const std::size_t num_nodes = (std::size_t{1} << (layers + 1)) - 1;
            const double root_speedup =
                best_root.available && best_root.wall_ms > 0.0 ? best_cpu.ms / best_root.wall_ms : 0.0;
            const double witness_speedup =
                best_witness.available && best_witness.wall_ms > 0.0 ? best_cpu.ms / best_witness.wall_ms : 0.0;

            std::printf("%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%.3f,%s\n",
                        n, num_nodes, best_cpu.ms, best_root.h2d_ms, best_root.kernel_ms,
                        best_root.d2h_ms, best_root.wall_ms, best_witness.wall_ms,
                        root_speedup, witness_speedup,
                        best_root.available ? (correct ? "PASS" : "FAIL") : "GPU_UNAVAILABLE");
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bench_merkle_sha256_compare error: %s\n", e.what());
        return 2;
    }
}
