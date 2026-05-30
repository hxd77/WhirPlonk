#include "whir/algebra/embedding.hpp"
#include "whir/algebra/goldilocks.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/irs_commit.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/transcript/transcript.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
#include <cuda_runtime.h>
#endif

using F = whir::algebra::Goldilocks;

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

whir::transcript::DomainSeparator make_ds(const char* session, std::size_t session_len) {
    whir::transcript::DomainSeparator ds;
    std::uint8_t cbor_proto[] = {0x19, 0xC0, 0xDA};
    sha3_512_hash(cbor_proto, 3, ds.protocol_id.data());
    sha3_256_hash(reinterpret_cast<const std::uint8_t*>(session), session_len, ds.session_id.data());
    return ds;
}

} // namespace

TEST(CudaIrsCommit, Sha2CommitOpenVerifyUsesGpuMerklePath) {
    if (!has_cuda_device()) GTEST_SKIP() << "CUDA device unavailable";

#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
    const bool old_enabled = whir::cuda::gpu_dispatch_enabled();
    const std::size_t old_threshold = whir::cuda::gpu_ntt_threshold();
    whir::cuda::set_gpu_dispatch_enabled(true);
    whir::cuda::set_gpu_ntt_threshold(0);

    constexpr std::size_t nv = 2;
    constexpr std::size_t vsz = 256;
    constexpr std::size_t depth = 4;
    constexpr std::size_t cw = 1024;
    constexpr std::size_t ood = 1;
    constexpr std::size_t ind = 8;

    Lcg rng(0x43554441495253ULL);
    std::vector<std::vector<F>> vecs(nv);
    for (auto& vec : vecs) {
        vec.resize(vsz);
        for (auto& v : vec) v = F::from_u64(rng.next());
    }
    std::vector<std::span<const F>> spans;
    for (const auto& v : vecs) spans.emplace_back(v);

    using Emb = whir::algebra::Identity<F>;
    whir::protocols::irs_commit::Config<Emb> config;
    config.num_vectors = nv;
    config.vector_size = vsz;
    config.codeword_length = cw;
    config.interleaving_depth = depth;
    config.matrix_commit_num_cols = nv * depth;
    config.in_domain_samples = ind;
    config.out_domain_samples = ood;
    config.deduplicate_in_domain = true;
    config.matrix_commit_mt = whir::protocols::merkle_tree::make_config(
        whir::hash::ENGINE_ID_SHA2, cw);

    const auto ds = make_ds("cuda-irs", 8);
    whir::transcript::Empty instance;
    auto ps = whir::transcript::ProverState::from_ds(ds, instance);
    auto witness = config.commit(ps, std::span<const std::span<const F>>{spans});

    EXPECT_TRUE(witness.matrix_witness.nodes.empty());
    EXPECT_EQ(witness.matrix_leaves.size(), cw);
    EXPECT_EQ(witness.matrix.size(), config.size());

    std::vector<const whir::protocols::irs_commit::Witness<F, F>*> wlist{&witness};
    auto in_domain = config.open(ps, std::span<const whir::protocols::irs_commit::Witness<F, F>*>{wlist});
    auto proof = std::move(ps).proof();

    auto vs = whir::transcript::VerifierState::from_ds(ds, instance, proof);
    auto commitment = config.receive_commitment(vs);
    std::vector<const whir::protocols::irs_commit::Commitment<F>*> clist{&commitment};
    auto verified = config.verify(vs, std::span<const whir::protocols::irs_commit::Commitment<F>*>{clist});

    EXPECT_EQ(in_domain.points, verified.points);
    EXPECT_EQ(in_domain.matrix, verified.matrix);
    EXPECT_TRUE(vs.check_eof());

    whir::cuda::set_gpu_ntt_threshold(old_threshold);
    whir::cuda::set_gpu_dispatch_enabled(old_enabled);
#endif
}
