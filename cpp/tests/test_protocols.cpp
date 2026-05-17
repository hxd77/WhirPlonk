// =============================================================================
// test_protocols.cpp — 协议层 GoogleTest 单元测试。
//
// 覆盖: NTT generator, interleaved RS encode, challenge_indices,
//       Merkle tree, proof of work, matrix_commit, sumcheck,
//       transcript, geometric_challenge, IRS commit,
//       WHIR 端到端, ZK WHIR 端到端。
// =============================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/embedding.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/mod_ntt.hpp"
#include "whir/algebra/utilities.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/challenge_indices.hpp"
#include "whir/protocols/matrix_commit.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/protocols/proof_of_work.hpp"
#include "whir/protocols/irs_commit.hpp"
#include "whir/protocols/sumcheck_protocol.hpp"
#include "whir/protocols/geometric_challenge.hpp"
#include "whir/protocols/whir/whir.hpp"
#include "whir/protocols/whir_zk/whir_zk.hpp"
#include "whir/transcript/transcript.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using F = ::whir::algebra::Goldilocks;

// ---- LCG 确定性随机数生成器 ----
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

// =============================================================================
// NTT Generator 测试
// =============================================================================

TEST(NttGenerator, ReturnsRootForValidSize) {
    auto g = ::whir::algebra::ntt::generator<F>(8);
    ASSERT_TRUE(g.has_value());
    EXPECT_EQ(g->pow(8), F::one());
    EXPECT_NE(g->pow(4), F::one());
}

TEST(NttGenerator, ReturnsNulloptForInvalidSize) {
    auto g = ::whir::algebra::ntt::generator<F>(3);
    EXPECT_FALSE(g.has_value());
}

TEST(NttGenerator, SizeOneReturnsOne) {
    auto g = ::whir::algebra::ntt::generator<F>(1);
    ASSERT_TRUE(g.has_value());
    EXPECT_EQ(*g, F::one());
}

// =============================================================================
// Interleaved RS Encode 测试
// =============================================================================

TEST(InterleavedRsEncode, BasicEncoding) {
    Lcg rng(0xDEAD);
    std::vector<F> vec(4);
    for (auto& v : vec) v = F::from_u64(rng.next());
    std::vector<std::span<const F>> coeffs{vec};

    auto matrix = ::whir::algebra::ntt::interleaved_rs_encode<F>(
        ::whir::algebra::ntt::goldilocks_engine(), coeffs, 8, 1);

    EXPECT_EQ(matrix.size(), 8);
    bool all_zero = true;
    for (auto& v : matrix) if (v != F::zero()) all_zero = false;
    EXPECT_FALSE(all_zero);
}

// =============================================================================
// Challenge Indices 测试
// =============================================================================

TEST(ChallengeIndices, EmptyCount) {
    auto indices = ::whir::protocols::challenge_indices::indices_from_entropy(
        std::span<const uint8_t>{}, 8, 0, false);
    EXPECT_TRUE(indices.empty());
}

TEST(ChallengeIndices, SingleLeaf) {
    std::vector<uint8_t> entropy(2, 0);
    auto indices = ::whir::protocols::challenge_indices::indices_from_entropy(
        entropy, 1, 2, false);
    EXPECT_EQ(indices.size(), 2);
    EXPECT_EQ(indices[0], 0);
    EXPECT_EQ(indices[1], 0);
}

TEST(ChallengeIndices, DedupWorks) {
    std::vector<uint8_t> entropy = {3, 3, 7, 7};
    auto indices = ::whir::protocols::challenge_indices::indices_from_entropy(
        entropy, 8, 4, true);
    EXPECT_LE(indices.size(), 2);
}

TEST(ChallengeIndices, NoDedupKeepsAll) {
    std::vector<uint8_t> entropy = {3, 3, 7, 7};
    auto indices = ::whir::protocols::challenge_indices::indices_from_entropy(
        entropy, 8, 4, false);
    EXPECT_EQ(indices.size(), 4);
}

// =============================================================================
// Merkle Tree 测试
// =============================================================================

TEST(MerkleTree, BasicTree) {
    ::whir::hash::Sha2 engine;
    std::vector<::whir::hash::Hash> leaves(4);
    for (std::size_t i = 0; i < 4; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);
        engine.hash_many(1, std::span<const uint8_t>{&byte, 1},
            std::span<::whir::hash::Hash>{&leaves[i], 1});
    }

    auto config = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, 4);
    auto el = [](::whir::EngineId) -> const ::whir::hash::HashEngine& {
        static ::whir::hash::Sha2 e; return e;
    };

    auto w = ::whir::protocols::merkle_tree::build_tree(config, leaves, el);
    auto root = ::whir::protocols::merkle_tree::tree_root(w);
    EXPECT_EQ(w.nodes.size(), config.num_nodes());

    std::size_t indices_arr[] = {0, 2};
    auto hints = ::whir::protocols::merkle_tree::open_path(config, w, indices_arr);
    std::vector<::whir::hash::Hash> test_leaves = {leaves[0], leaves[2]};
    bool ok = ::whir::protocols::merkle_tree::verify_path(
        config, root, std::span<const std::size_t>{indices_arr},
        test_leaves, hints, el);
    EXPECT_TRUE(ok);
}

// =============================================================================
// Proof of Work 测试
// =============================================================================

TEST(ProofOfWork, ZeroDifficulty) {
    ::whir::protocols::pow::PowConfig config;
    // threshold_val == UINT64_MAX → 零难度, 任何 nonce 通过
    EXPECT_EQ(config.threshold_val, UINT64_MAX);
    // check_nonce 在零难度下总是 true
    ::whir::hash::Sha2 engine;
    std::array<uint8_t, 32> challenge{};
    EXPECT_TRUE(::whir::protocols::pow::check_nonce(engine, challenge, 0, UINT64_MAX));
}

TEST(ProofOfWork, FindNonceZeroDifficulty) {
    // 零难度下 find_nonce 返回 0 即可
    ::whir::hash::Sha2 engine;
    std::array<uint8_t, 32> challenge{};
    uint64_t nonce = ::whir::protocols::pow::find_nonce(engine, challenge, UINT64_MAX);
    // 零难度下任何 nonce 都行, find_nonce 返回第一个尝试的 nonce (0)
    EXPECT_TRUE(::whir::protocols::pow::check_nonce(engine, challenge, nonce, UINT64_MAX));
}

TEST(ProofOfWork, ThresholdRoundTrip) {
    // 低难度: threshold = UINT64_MAX / 2 (前 1 位必须为零)
    ::whir::hash::Sha2 engine;
    std::array<uint8_t, 32> challenge{};
    uint64_t threshold = UINT64_MAX >> 1;
    uint64_t nonce = ::whir::protocols::pow::find_nonce(engine, challenge, threshold);
    EXPECT_TRUE(::whir::protocols::pow::check_nonce(engine, challenge, nonce, threshold));
}

// =============================================================================
// Sumcheck 集成测试
// =============================================================================

::whir::transcript::DomainSeparator make_ds(const char* session, std::size_t session_len) {
    ::whir::transcript::DomainSeparator ds;
    uint8_t cbor_proto[] = {0x19, 0xAB, 0xCD};
    sha3_512_hash(cbor_proto, 3, ds.protocol_id.data());
    sha3_256_hash(reinterpret_cast<const uint8_t*>(session), session_len, ds.session_id.data());
    return ds;
}

TEST(SumcheckIntegration, ProveVerifyCycle) {
    Lcg rng(0x1234);
    std::vector<F> a(8), b(8);
    for (auto& v : a) v = F::from_u64(rng.next());
    for (auto& v : b) v = F::from_u64(rng.next());

    // 计算内积
    F claim = F::zero();
    for (std::size_t i = 0; i < 8; ++i) claim += a[i] * b[i];

    ::whir::protocols::sumcheck::Config<F> sc_config;
    sc_config.initial_size = 8;
    sc_config.num_rounds = 3;  // log2(8) = 3

    auto ds = make_ds("sumcheck_t1", 11);
    ::whir::transcript::Empty instance;

    // Prover
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    auto a_copy = a, b_copy = b;
    F sum = claim;
    auto fr = sc_config.prove(ps, a_copy, b_copy, sum);
    auto proof = std::move(ps).proof();
    EXPECT_EQ(fr.coords.size(), 3);

    // Verifier
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    F v_sum = claim;
    auto v_fr = sc_config.verify(vs, v_sum);
    EXPECT_EQ(v_fr.coords.size(), 3);
    EXPECT_TRUE(vs.check_eof());
}

TEST(SumcheckIntegration, EmptySumcheck) {
    ::whir::protocols::sumcheck::Config<F> sc_config;
    sc_config.initial_size = 1;
    sc_config.num_rounds = 0;

    auto ds = make_ds("sc_empty", 8);
    ::whir::transcript::Empty instance;

    std::vector<F> a = {F::from_u64(42)};
    std::vector<F> b = {F::from_u64(7)};
    F claim = a[0] * b[0];

    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    auto a2 = a, b2 = b;
    F sum = claim;
    auto fr = sc_config.prove(ps, a2, b2, sum);
    // num_rounds=0 时无折叠, coords 为空
    EXPECT_EQ(fr.coords.size(), 0);

    auto proof = std::move(ps).proof();
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    F v_sum = claim;
    auto v_fr = sc_config.verify(vs, v_sum);
    EXPECT_EQ(v_fr.coords.size(), 0);
    EXPECT_TRUE(vs.check_eof());
}

// =============================================================================
// Transcript 集成测试
// =============================================================================

TEST(TranscriptIntegration, RoundTrip) {
    auto ds = make_ds("ts_round", 8);
    ::whir::transcript::Empty instance;

    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    ps.prover_message(F::from_u64(0xCAFEBABE));
    auto c0 = ps.verifier_message<F>();
    ps.prover_message(F::from_u64(0xDEADBEEF));
    auto c1 = ps.verifier_message<F>();
    auto proof = std::move(ps).proof();

    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    F m0, m1;
    vs.prover_message(m0);
    EXPECT_EQ(m0, F::from_u64(0xCAFEBABE));
    auto vc0 = vs.verifier_message<F>();
    EXPECT_EQ(vc0, c0);
    vs.prover_message(m1);
    EXPECT_EQ(m1, F::from_u64(0xDEADBEEF));
    auto vc1 = vs.verifier_message<F>();
    EXPECT_EQ(vc1, c1);
    EXPECT_TRUE(vs.check_eof());
}

// =============================================================================
// Geometric Challenge 测试
// =============================================================================

TEST(GeometricChallenge, ProducesGeometricSequence) {
    auto ds = make_ds("geo_chal", 8);
    ::whir::transcript::Empty instance;
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);

    auto seq = ::whir::protocols::geometric_challenge<F>(ps, 5);
    ASSERT_EQ(seq.size(), 5);
    EXPECT_EQ(seq[0], F::one());
    if (seq.size() >= 2 && seq[1] != F::zero()) {
        F ratio = seq[1] * seq[0].inverse();
        for (std::size_t i = 2; i < seq.size(); ++i)
            EXPECT_EQ(seq[i], seq[i - 1] * ratio);
    }
}

// =============================================================================
// IRS Commit 集成测试
// =============================================================================

TEST(IrsCommitIntegration, CommitAndVerify) {
    Lcg rng(0xBABE);
    const std::size_t nv = 1, vsz = 4, depth = 1, cw = 8, ood = 1, ind = 2;
    const std::size_t ncols = nv * depth;

    std::vector<std::vector<F>> vecs(nv);
    for (auto& vec : vecs) {
        vec.resize(vsz);
        for (auto& v : vec) v = F::from_u64(rng.next());
    }
    std::vector<std::span<const F>> spans;
    for (auto& v : vecs) spans.push_back(v);

    using Emb = ::whir::algebra::Identity<F>;
    ::whir::protocols::irs_commit::Config<Emb> config;
    config.num_vectors = nv;
    config.vector_size = vsz;
    config.codeword_length = cw;
    config.interleaving_depth = depth;
    config.matrix_commit_num_cols = ncols;
    config.in_domain_samples = ind;
    config.out_domain_samples = ood;
    config.deduplicate_in_domain = false;
    config.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, cw);

    auto ds = make_ds("irs1", 4);
    ::whir::transcript::Empty instance;
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    auto witness = config.commit(ps, spans);
    std::vector<const ::whir::protocols::irs_commit::Witness<F, F>*> wlist{&witness};
    auto in_domain = config.open(ps, wlist);
    auto proof = std::move(ps).proof();

    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    auto commitment = config.receive_commitment(vs);
    std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> clist{&commitment};
    auto v_in_domain = config.verify(vs, clist);
    EXPECT_EQ(in_domain.points, v_in_domain.points);
    EXPECT_EQ(in_domain.matrix, v_in_domain.matrix);
    EXPECT_TRUE(vs.check_eof());
}

// =============================================================================
// End-to-End: Sumcheck → IRS Commit
// =============================================================================

TEST(EndToEnd, MiniSumcheckToIrsCommit) {
    Lcg rng(0xABCD);
    std::vector<F> a(4), b(4);
    for (auto& v : a) v = F::from_u64(rng.next());
    for (auto& v : b) v = F::from_u64(rng.next());
    F claim = F::zero();
    for (std::size_t i = 0; i < 4; ++i) claim += a[i] * b[i];

    auto ds = make_ds("e2e1", 4);
    ::whir::protocols::sumcheck::Config<F> sc;
    sc.initial_size = 4;
    sc.num_rounds = 2;

    ::whir::transcript::Empty instance;
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    auto a2 = a, b2 = b;
    F sum = claim;
    auto fr = sc.prove(ps, a2, b2, sum);
    EXPECT_EQ(fr.coords.size(), 2);

    auto proof = std::move(ps).proof();
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    F v_sum = claim;
    auto vfr = sc.verify(vs, v_sum);
    EXPECT_EQ(fr.coords, vfr.coords);
    EXPECT_TRUE(vs.check_eof());
}

// =============================================================================
// WHIR 端到端测试 (最小参数, 1 轮)
// =============================================================================

//TEST(TestSuiteName,TestName) TestSuiteName是逻辑分组,同一组测试中共享setup/teardown TestName:具体用例名 
TEST(WhirIntegration, FullProveVerifyCycle) { //WhirIntegration Test集成测试,FullProverVerifyCycle完整的证明-验证周期
    Lcg rng(0xCAFE);
    const std::size_t initial_size = 8;

    //初始化vector
    std::vector<F> vec(initial_size);
    for (auto& v : vec) v = F::from_u64(rng.next());
    
    //把vec->span
    std::vector<std::span<const F>> vec_spans{vec}; 

    //创建一个Convector对象,并用if智能指针管理它
    auto lf = std::make_unique<::whir::algebra::Covector<F>>(
        std::vector<F>(initial_size, F::one())); 

    //创建一个数组,类型是父类LinearForm
    std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> linear_forms;
    F eval = F::zero();
    for (auto& v : vec) eval += v;
    std::vector<F> evaluations = {eval};
    linear_forms.push_back(std::move(lf));

    using Emb = ::whir::algebra::Identity<F>;

    // 初始 IRS 配置
    ::whir::protocols::irs_commit::Config<Emb> initial_committer;
    initial_committer.num_vectors = 1; //1个多项式
    initial_committer.vector_size = initial_size; //多项式系数
    initial_committer.codeword_length = 16; //编码后长度
    initial_committer.interleaving_depth = 1;
    initial_committer.matrix_commit_num_cols = 1;
    initial_committer.in_domain_samples = 2; //域内点
    initial_committer.out_domain_samples = 1; //域外点
    initial_committer.deduplicate_in_domain = false; //不去重
    initial_committer.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, 16); //构造Merkle tree

    // 初始 sumcheck
    ::whir::protocols::sumcheck::Config<F> initial_sumcheck;
    initial_sumcheck.initial_size = 8;
    initial_sumcheck.num_rounds = 2;

    // 一轮折叠配置
    ::whir::protocols::whir::RoundConfig<F> rc;
    rc.irs_committer.num_vectors = 1;
    rc.irs_committer.vector_size = 4;
    rc.irs_committer.codeword_length = 8;
    rc.irs_committer.interleaving_depth = 1;
    rc.irs_committer.matrix_commit_num_cols = 1;
    rc.irs_committer.in_domain_samples = 2;
    rc.irs_committer.out_domain_samples = 1;
    rc.irs_committer.deduplicate_in_domain = false;
    rc.irs_committer.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, 8);
    rc.sumcheck.initial_size = 4;
    rc.sumcheck.num_rounds = 1;
    // PowConfig 默认 threshold_val = UINT64_MAX (零难度)

    // 最终 sumcheck
    ::whir::protocols::sumcheck::Config<F> final_sumcheck;
    final_sumcheck.initial_size = 2;
    final_sumcheck.num_rounds = 1;

    // PowConfig 默认零难度
    ::whir::protocols::pow::PowConfig default_pow;

    // 组装 WHIR Config
    ::whir::protocols::whir::Config<Emb> whir_config;
    whir_config.initial_committer = initial_committer;
    whir_config.initial_sumcheck = initial_sumcheck;
    whir_config.initial_skip_pow = default_pow;
    whir_config.round_configs.push_back(rc);
    whir_config.final_sumcheck = final_sumcheck;
    whir_config.final_pow = default_pow;

    auto ds = make_ds("whir_t1", 7);
    ::whir::transcript::Empty instance;

    // Prover
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance); //1.创建Fiat-Shamir 证明者状态 
    auto witness = whir_config.commit(ps, vec_spans); //2. 多项式承诺
    std::vector<::whir::protocols::irs_commit::Witness<F, F>> whir_witnesses; 
    whir_witnesses.push_back(witness); 

    auto claim = whir_config.prove(ps, vec_spans,
        std::span<const ::whir::protocols::irs_commit::Witness<F, F>>{whir_witnesses},
        std::move(linear_forms), evaluations); //3.生成承诺
    auto proof = std::move(ps).proof(); //提取序列化证明

    //EXPECT -失败后继续执行后续断言
    EXPECT_FALSE(claim.evaluation_point.empty());
    EXPECT_FALSE(claim.rlc_coefficients.empty());

    // Verifier
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    auto commitment = whir_config.receive_commitment(vs);
    std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> cptrs{&commitment};
    auto v_claim = whir_config.verify(vs, cptrs, evaluations);

    // 验证协议完成 (prover 和 verifier 的求值点尾部应一致)
    EXPECT_FALSE(v_claim.evaluation_point.empty());
    EXPECT_EQ(claim.rlc_coefficients, v_claim.rlc_coefficients);
    EXPECT_TRUE(vs.check_eof());
}

// =============================================================================
// ZK WHIR 端到端测试
// =============================================================================

TEST(ZkWhirIntegration, FullProveVerifyCycle) {
    Lcg rng(0xF00D);
    const std::size_t initial_size = 8;

    std::vector<F> vec(initial_size);
    for (auto& v : vec) v = F::from_u64(rng.next());
    std::vector<std::span<const F>> poly_spans{vec};

    auto lf = std::make_unique<::whir::algebra::Covector<F>>(
        std::vector<F>(initial_size, F::one()));
    std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> linear_forms;
    F eval = F::zero();
    for (auto& v : vec) eval += v;
    std::vector<F> evaluations = {eval};
    linear_forms.push_back(std::move(lf));

    using Emb = ::whir::algebra::Identity<F>;
    ::whir::protocols::whir_zk::ZkConfig<F> zk_config;

    // ---- blinded_commitment ----
    auto& bc = zk_config.blinded_commitment;
    bc.initial_committer.num_vectors = 1;
    bc.initial_committer.vector_size = initial_size;
    bc.initial_committer.codeword_length = 16;
    bc.initial_committer.interleaving_depth = 1;
    bc.initial_committer.matrix_commit_num_cols = 1;
    bc.initial_committer.in_domain_samples = 2;
    bc.initial_committer.out_domain_samples = 1;
    bc.initial_committer.deduplicate_in_domain = false;
    bc.initial_committer.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, 16);
    bc.initial_sumcheck.initial_size = 8;
    bc.initial_sumcheck.num_rounds = 2;
    bc.initial_skip_pow.threshold_val = UINT64_MAX;

    ::whir::protocols::whir::RoundConfig<F> bc_rc;
    bc_rc.irs_committer.num_vectors = 1;
    bc_rc.irs_committer.vector_size = 4;
    bc_rc.irs_committer.codeword_length = 8;
    bc_rc.irs_committer.interleaving_depth = 1;
    bc_rc.irs_committer.matrix_commit_num_cols = 1;
    bc_rc.irs_committer.in_domain_samples = 2;
    bc_rc.irs_committer.out_domain_samples = 1;
    bc_rc.irs_committer.deduplicate_in_domain = false;
    bc_rc.irs_committer.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, 8);
    bc_rc.sumcheck.initial_size = 4;
    bc_rc.sumcheck.num_rounds = 1;
    bc.round_configs.push_back(bc_rc);
    bc.final_sumcheck.initial_size = 2;
    bc.final_sumcheck.num_rounds = 1;

    // ---- blinding_commitment ----
    auto& blc = zk_config.blinding_commitment;
    blc.initial_committer.num_vectors = 4;  // mu+1 = 4
    blc.initial_committer.vector_size = 4;   // 2^(ell+1), ell=1
    blc.initial_committer.codeword_length = 8;
    blc.initial_committer.interleaving_depth = 1;
    blc.initial_committer.matrix_commit_num_cols = 4;
    blc.initial_committer.in_domain_samples = 2;
    blc.initial_committer.out_domain_samples = 1;
    blc.initial_committer.deduplicate_in_domain = false;
    blc.initial_committer.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, 8);
    blc.initial_sumcheck.initial_size = 4;
    blc.initial_sumcheck.num_rounds = 1;
    blc.initial_skip_pow.threshold_val = UINT64_MAX;

    ::whir::protocols::whir::RoundConfig<F> bl_rc;
    bl_rc.irs_committer.num_vectors = 1;
    bl_rc.irs_committer.vector_size = 2;
    bl_rc.irs_committer.codeword_length = 4;
    bl_rc.irs_committer.interleaving_depth = 1;
    bl_rc.irs_committer.matrix_commit_num_cols = 1;
    bl_rc.irs_committer.in_domain_samples = 2;
    bl_rc.irs_committer.out_domain_samples = 1;
    bl_rc.irs_committer.deduplicate_in_domain = false;
    bl_rc.irs_committer.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, 4);
    bl_rc.sumcheck.initial_size = 2;
    bl_rc.sumcheck.num_rounds = 1;
    blc.round_configs.push_back(bl_rc);
    blc.final_sumcheck.initial_size = 1;
    blc.final_sumcheck.num_rounds = 0;

    auto ds = make_ds("zk_whir1", 8);
    ::whir::transcript::Empty instance;

    // Prover commit
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    auto zk_witness = zk_config.commit(ps, poly_spans, rng);

    // Prover prove
    std::vector<F> vec_flat(vec.begin(), vec.end());
    auto claim = zk_config.prove(ps, vec_flat, std::move(zk_witness),
        std::move(linear_forms), evaluations, rng);
    auto proof = std::move(ps).proof();

    EXPECT_FALSE(claim.evaluation_point.empty());

    // Verifier
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    auto zk_commitment = zk_config.receive_commitments(vs, 1);

    ::whir::algebra::Covector<F> verifier_lf(std::vector<F>(initial_size, F::one()));
    std::vector<const ::whir::algebra::LinearForm<F>*> v_lf_ptrs{&verifier_lf};

    bool ok = zk_config.verify(vs, v_lf_ptrs, evaluations, zk_commitment);
    EXPECT_TRUE(ok);
    // ZK WHIR 验证内部有两个 WHIR verify 调用, eof 由最终状态决定
}
