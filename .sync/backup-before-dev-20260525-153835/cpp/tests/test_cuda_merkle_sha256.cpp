#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/merkle_tree.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include <gtest/gtest.h>

#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
#include "cuda/cuda_integration.hpp"
#include <cuda_runtime.h>
#endif

using whir::hash::Hash;

namespace {

struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
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

std::vector<Hash> make_leaves(std::size_t n) {
    Lcg rng(0x4d45524b4c455346ULL ^ static_cast<uint64_t>(n));
    std::vector<Hash> leaves(n);
    for (auto& h : leaves) {
        for (auto& b : h) b = static_cast<std::uint8_t>(rng.next() >> 56);
    }
    return leaves;
}

std::vector<Hash> cpu_tree_nodes(const std::vector<Hash>& leaves) {
    whir::hash::Sha2 sha2;
    const auto config = whir::protocols::merkle_tree::make_config(
        whir::hash::ENGINE_ID_SHA2, leaves.size());
    auto witness = whir::protocols::merkle_tree::build_tree(
        config, leaves,
        [&](const whir::EngineId&) -> const whir::hash::HashEngine& { return sha2; });
    return witness.nodes;
}

} // namespace

TEST(CudaMerkleSha256, MatchesCpuWitnessNodesAndRoot) {
    if (!has_cuda_device()) GTEST_SKIP() << "CUDA device unavailable";

    constexpr std::array<std::size_t, 7> cases{0, 1, 2, 3, 17, 1024, 65536};
    for (const std::size_t n : cases) {
        const auto leaves = make_leaves(n);
        const auto cpu_nodes = cpu_tree_nodes(leaves);

#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
        std::vector<Hash> gpu_nodes(cpu_nodes.size());
        Hash gpu_root{};
        whir::cuda::gpu_sha256_merkle_tree(
            reinterpret_cast<const std::uint8_t*>(leaves.data()),
            leaves.size(), gpu_root.data(),
            reinterpret_cast<std::uint8_t*>(gpu_nodes.data()));

        EXPECT_EQ(cpu_nodes, gpu_nodes) << "num_leaves=" << n;
        ASSERT_FALSE(cpu_nodes.empty());
        EXPECT_EQ(cpu_nodes.back(), gpu_root) << "num_leaves=" << n;

        Hash gpu_root_only{};
        whir::cuda::gpu_sha256_merkle_tree(
            reinterpret_cast<const std::uint8_t*>(leaves.data()),
            leaves.size(), gpu_root_only.data());
        EXPECT_EQ(cpu_nodes.back(), gpu_root_only) << "num_leaves=" << n;
#endif
    }
}
