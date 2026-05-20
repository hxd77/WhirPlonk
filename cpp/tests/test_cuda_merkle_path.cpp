#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/transcript/transcript.hpp"

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
    Lcg rng(0x4d45524b50415448ULL ^ static_cast<uint64_t>(n));
    std::vector<Hash> leaves(n);
    for (auto& h : leaves) {
        for (auto& b : h) b = static_cast<std::uint8_t>(rng.next() >> 56);
    }
    return leaves;
}

std::vector<std::size_t> make_indices(std::size_t n) {
    if (n == 1) return {0};
    return {0, 1, n / 3, n / 2, n - 2, n - 1, n / 2};
}

} // namespace

TEST(CudaMerklePath, MatchesCpuOpenPathHints) {
    if (!has_cuda_device()) GTEST_SKIP() << "CUDA device unavailable";

    constexpr std::array<std::size_t, 7> cases{1, 2, 3, 17, 1024, 65536, 262144};
    for (const std::size_t n : cases) {
        const auto leaves = make_leaves(n);
        const auto indices = make_indices(n);
        whir::hash::Sha2 sha2;
        const auto config = whir::protocols::merkle_tree::make_config(
            whir::hash::ENGINE_ID_SHA2, leaves.size());
        auto witness = whir::protocols::merkle_tree::build_tree(
            config, leaves,
            [&](const whir::EngineId&) -> const whir::hash::HashEngine& { return sha2; });
        const auto cpu_hints = whir::protocols::merkle_tree::open_path(
            config, witness, std::span<const std::size_t>{indices});

#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
        const auto hint_nodes = whir::cuda::merkle_hint_node_indices(
            leaves.size(), std::span<const std::size_t>{indices});
        ASSERT_EQ(cpu_hints.size(), hint_nodes.size()) << "num_leaves=" << n;

        Hash gpu_root{};
        std::vector<Hash> gpu_hints(cpu_hints.size());
        whir::cuda::gpu_sha256_merkle_open_path(
            reinterpret_cast<const std::uint8_t*>(leaves.data()),
            leaves.size(), std::span<const std::size_t>{indices}, gpu_root.data(),
            reinterpret_cast<std::uint8_t*>(gpu_hints.data()));

        EXPECT_EQ(witness.nodes.back(), gpu_root) << "num_leaves=" << n;
        EXPECT_EQ(cpu_hints, gpu_hints) << "num_leaves=" << n;
        std::vector<Hash> queried_leaves;
        queried_leaves.reserve(indices.size());
        for (std::size_t idx : indices) queried_leaves.push_back(leaves[idx]);
        EXPECT_TRUE(whir::protocols::merkle_tree::verify_path(
            config, gpu_root, std::span<const std::size_t>{indices},
            std::span<const Hash>{queried_leaves},
            std::span<const Hash>{gpu_hints},
            [&](const whir::EngineId&) -> const whir::hash::HashEngine& { return sha2; }));
#endif
    }
}

TEST(CudaMerklePath, TranscriptOpenVerifyLargeTree) {
    const std::size_t n = std::size_t{1} << 18;
    const auto leaves = make_leaves(n);
    const auto indices = make_indices(n);
    std::vector<Hash> queried_leaves;
    queried_leaves.reserve(indices.size());
    for (std::size_t idx : indices) queried_leaves.push_back(leaves[idx]);

    whir::hash::Sha2 sha2;
    const auto config = whir::protocols::merkle_tree::make_config(
        whir::hash::ENGINE_ID_SHA2, leaves.size());
    auto witness = whir::protocols::merkle_tree::build_tree(
        config, leaves,
        [&](const whir::EngineId&) -> const whir::hash::HashEngine& { return sha2; });

    whir::transcript::ProverState ps;
    whir::protocols::merkle_tree::open(ps, config, witness, std::span<const std::size_t>{indices});
    auto proof = std::move(ps).proof();
    whir::transcript::DomainSeparator ds;
    whir::transcript::Empty instance;
    auto vs = whir::transcript::VerifierState::from_ds(ds, instance, proof);
    EXPECT_TRUE(whir::protocols::merkle_tree::verify(
        vs, config, whir::protocols::merkle_tree::Commitment{witness.nodes.back()},
        std::span<const std::size_t>{indices}, std::span<const Hash>{queried_leaves},
        [&](const whir::EngineId&) -> const whir::hash::HashEngine& { return sha2; }));
    EXPECT_TRUE(vs.check_eof());
}
