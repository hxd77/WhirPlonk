// ===========================================================================
// dump_whir.cpp — WHIR 协议 golden test (跨语言对拍基准, 多 case)
//
// 输入:  确定性 RNG (seed=0xCAFE), 每个 case 独立的协议参数
// 输出:  标准输出 — 每个 case 以 "CASE N" 分隔, 含协议各阶段中间值和 proof
//        与 Rust 端 examples/dump_whir.rs 输出格式完全一致, 可直接 diff
//
// 运行:
//   ./dump_whir > golden_whir_cpp.txt
//   diff golden_whir_rs.txt golden_whir_cpp.txt
//
// Case 覆盖:
//   CASE 0: 1 多项式 × 2 系数  (最小可用)
//   CASE 1: 1 多项式 × 4 系数
//   CASE 2: 1 多项式 × 8 系数
//   CASE 3: 3 多项式 × 4 系数  (多向量)
//   CASE 4: 4 多项式 × 8 系数  (多向量, 大参数)
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/embedding.hpp"
#include "whir/algebra/linear_form.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/utilities.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/irs_commit.hpp"
#include "whir/protocols/matrix_commit.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/protocols/proof_of_work.hpp"
#include "whir/protocols/sumcheck_protocol.hpp"
#include "whir/protocols/whir/whir.hpp"
#include "whir/transcript/transcript.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using F = ::whir::algebra::Goldilocks;
using Emb = ::whir::algebra::Identity<F>;

// ---- 确定性 RNG (与 Rust Lcg 完全一致) ----
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

// ---- 输出辅助函数 ----

void dump_bytes(const char* label, const auto& data) {
    std::printf("    %s ", label);
    for (auto b : data) std::printf("%02x", static_cast<unsigned>(b));
    std::printf("\n");
}

void dump_field_vec(const char* label, const std::vector<F>& vec) {
    std::printf("    %s", label);
    for (auto& v : vec) std::printf(" %llu", (unsigned long long)v.as_canonical_u64());
    std::printf("\n");
}

// ---- DomainSeparator 构造 (所有 case 共用) ----
::whir::transcript::DomainSeparator make_ds(const char* session_label) {
    ::whir::transcript::DomainSeparator ds;
    uint8_t cbor_proto[] = {0x19, 0xBE, 0xEF};
    sha3_512_hash(cbor_proto, 3, ds.protocol_id.data());
    // session = CBOR("whir_") + label, 区分不同 case 的海绵状态
    std::string label_str = std::string("whir_") + session_label;
    std::vector<uint8_t> cbor_sess;
    cbor_sess.push_back(0x60 + static_cast<uint8_t>(label_str.size())); // CBOR text header
    for (char c : label_str) cbor_sess.push_back(static_cast<uint8_t>(c));
    sha3_256_hash(cbor_sess.data(), cbor_sess.size(), ds.session_id.data());
    return ds;
}

// ---- 单个 WHIR 测试 case ----
// 参数:
//   case_id      — 用于输出标识和 session 区分
//   num_vectors  — 多项式数量
//   vector_size  — 每个多项式的系数个数 (必须是 2 的幂)
//   rng          — 确定性随机数生成器 (被推进)
// 输出: 标准输出, 格式 "CASE N" + 协议各阶段值
void run_case(int case_id, std::size_t num_vectors, std::size_t vector_size, Lcg& rng) {
    std::size_t depth = 1;
    std::size_t cw = vector_size * 2;       // codeword = 2 * vector_size
    std::size_t num_cols = num_vectors * depth;
    std::size_t ood = 1;                    // 域外采样数
    std::size_t ind = std::min(vector_size, std::size_t{3}); // 域内采样 (≤ 向量大小)
    std::size_t log_vs = 0;
    { std::size_t sz = vector_size; while (sz > 1) { sz >>= 1; ++log_vs; } }

    std::printf("CASE %d\n", case_id);

    // ---- 1. 输入构造 ----
    // 每个多项式生成随机系数
    std::vector<std::vector<F>> vecs(num_vectors);
    std::vector<std::span<const F>> vec_spans;
    std::vector<F> evaluations;

    for (std::size_t vi = 0; vi < num_vectors; ++vi) {
        vecs[vi].resize(vector_size);
        for (auto& v : vecs[vi]) v = F::from_u64(rng.next());
        vec_spans.push_back(vecs[vi]);
        // 全 1 线性形式在每向量上的求值 = 系数之和
        F eval = F::zero();
        for (auto& v : vecs[vi]) eval += v;
        evaluations.push_back(eval);
        dump_field_vec(("input_vector" + std::to_string(vi)).c_str(), vecs[vi]);
    }

    // 一个全 1 线性形式 (对所有多项式通用)
    auto lf = std::make_unique<::whir::algebra::Covector<F>>(
        std::vector<F>(vector_size, F::one()));
    std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> linear_forms;
    linear_forms.push_back(std::move(lf));

    // ---- 2. 协议配置 ----
    ::whir::protocols::irs_commit::Config<Emb> initial_committer;
    initial_committer.num_vectors = num_vectors;
    initial_committer.vector_size = vector_size;
    initial_committer.codeword_length = cw;
    initial_committer.interleaving_depth = depth;
    initial_committer.matrix_commit_num_cols = num_cols;
    initial_committer.in_domain_samples = ind;
    initial_committer.out_domain_samples = ood;
    initial_committer.deduplicate_in_domain = false;
    initial_committer.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, cw);

    ::whir::protocols::sumcheck::Config<F> initial_sumcheck;
    initial_sumcheck.initial_size = vector_size;
    initial_sumcheck.num_rounds = 0;

    ::whir::protocols::sumcheck::Config<F> final_sumcheck;
    final_sumcheck.initial_size = vector_size;
    final_sumcheck.num_rounds = log_vs;  // fold: vector_size → 1

    ::whir::protocols::whir::Config<Emb> whir_config;
    whir_config.initial_committer = initial_committer;
    whir_config.initial_sumcheck = initial_sumcheck;
    whir_config.initial_skip_pow = {};
    whir_config.final_sumcheck = final_sumcheck;
    whir_config.final_pow = {};

    // ---- 3. DomainSeparator (每个 case 独立 session) ----
    auto ds = make_ds(std::to_string(case_id).c_str());
    ::whir::transcript::Empty instance;

    // ---- 4. Prover ----
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    auto witness = whir_config.commit(ps, vec_spans);

    dump_field_vec("witness_matrix", witness.matrix);
    dump_field_vec("ood_points", witness.out_of_domain.points);
    dump_field_vec("ood_matrix", witness.out_of_domain.matrix);

    std::vector<::whir::protocols::irs_commit::Witness<F, F>> whir_wits;
    whir_wits.push_back(std::move(witness));
    // 重新构造 spans (避免与 commit 内部移动冲突)
    std::vector<std::span<const F>> sp2;
    for (auto& v : vecs) sp2.push_back(v);

    auto claim = whir_config.prove(ps, sp2,
        std::span<const ::whir::protocols::irs_commit::Witness<F, F>>{whir_wits},
        std::move(linear_forms), evaluations);
    auto proof = std::move(ps).proof();

    dump_field_vec("eval_point", claim.evaluation_point);
    dump_field_vec("rlc_coeffs", claim.rlc_coefficients);
    dump_bytes("proof_narg", proof.narg_string);
    dump_bytes("proof_hints", proof.hints);

    // ---- 5. Verifier ----
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    auto comm = whir_config.receive_commitment(vs);
    std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> cp{&comm};
    auto vc = whir_config.verify(vs, cp, evaluations);

    dump_field_vec("v_eval_point", vc.evaluation_point);
    dump_field_vec("v_rlc_coeffs", vc.rlc_coefficients);
    std::printf("    check_eof %d\n", static_cast<int>(vs.check_eof()));
}

int main() {
    std::printf("# SECTION whir\n");

    Lcg rng(0xCAFE);

    // CASE 0: 1 多项式 × 2 系数 (最小)
    run_case(0, 1, 2, rng);

    // CASE 1: 1 多项式 × 4 系数
    run_case(1, 1, 4, rng);

    // CASE 2: 1 多项式 × 8 系数
    run_case(2, 1, 8, rng);

    // CASE 3: 3 多项式 × 4 系数 (多向量)
    run_case(3, 3, 4, rng);

    // CASE 4: 4 多项式 × 8 系数 (多向量 + 大参数)
    run_case(4, 4, 8, rng);

    return 0;
}
