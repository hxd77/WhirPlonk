#pragma once

// ============================================================================
// whir_zk_impl.hpp — ZK WHIR 协议方法实现
//
// 定义 ZkConfig 的四个模板方法:
//   commit()              — ZK 盲化承诺
//   receive_commitments() — 接收 ZK 承诺
//   prove()               — ZK WHIR 证明（11 步）
//   verify()              — ZK WHIR 验证（9 步）
//
// 由 whir_zk.hpp 在文件末尾包含。
//
// 对应 Rust 文件: src/protocols/whir_zk/{committer.rs, prover.rs, verifier.rs}
// ============================================================================

#include "../geometric_challenge.hpp"
#include "../../transcript/transcript.hpp"

#include <cassert>
#include <memory>
#include <span>

namespace whir::protocols::whir_zk {

// ============================================================================
// ZkConfig::commit() — 多项式的 ZK 盲化承诺
//
// prover_state — Fiat-Shamir transcript
// polynomials  — 原始多项式 (num_polys x 2^num_witness_vars)
// rng          — 用于采样盲化多项式的 RNG
//
// 对每个多项式:
//   1. 采样 BlindingPolynomials (m_poly, g_hats)
//   2. 构造 f_hat = f + mask（mask 以 m_poly.size() 为周期）
//   3. 通过 blinded_commitment 对 f_hat 做 WHIR 承诺
// 然后布局所有盲化向量，通过 blinding_commitment 做 WHIR 承诺
//
// 返回 ZkWitness
// ============================================================================

template <typename F>
template <typename Transcript, typename Rng>
ZkWitness<F> ZkConfig<F>::commit(
    Transcript& prover_state,
    std::span<const std::span<const F>> polynomials,
    Rng& rng) const
{
    std::size_t num_polys = polynomials.size();
    std::size_t num_blind_vars = num_blinding_variables();
    std::size_t num_wit_vars = num_witness_variables();

    std::vector<std::vector<F>> f_hat_vectors(num_polys);
    std::vector<::whir::protocols::irs_commit::Witness<F, F>> f_hat_witnesses(num_polys);
    std::vector<BlindingPolynomials<F>> blind_polys(num_polys);

    for (std::size_t pi = 0; pi < num_polys; ++pi) {
        // 采样盲化: m_poly（交织的 g0_hat + msk），g_hats（每个 witness 变量一个）
        auto bp = BlindingPolynomials<F>::sample(rng, num_blind_vars, num_wit_vars);
        const auto& mask = bp.m_poly;

        // f_hat = f + mask（mask 周期性应用）
        std::vector<F> f_hat(polynomials[pi].begin(), polynomials[pi].end());
        for (std::size_t i = 0; i < f_hat.size(); ++i)
            f_hat[i] = f_hat[i] + mask[i % mask.size()];

        // WHIR 承诺 f_hat
        std::vector<std::span<const F>> single_vec = {f_hat};
        auto witness = blinded_commitment.commit(prover_state, single_vec);

        f_hat_vectors[pi] = std::move(f_hat);
        f_hat_witnesses[pi] = std::move(witness);
        blind_polys[pi] = std::move(bp);
    }

    // 布局盲化向量: [M, g_hat_0^emb, ..., g_hat_{mu-1}^emb]
    std::vector<std::vector<F>> blind_vectors;
    for (const auto& bp : blind_polys) {
        auto layout = bp.layout_vectors();
        blind_vectors.insert(blind_vectors.end(),
            std::make_move_iterator(layout.begin()),
            std::make_move_iterator(layout.end()));
    }

    std::vector<std::span<const F>> blind_refs;
    blind_refs.reserve(blind_vectors.size());
    for (const auto& v : blind_vectors) blind_refs.push_back(v);

    // WHIR 承诺盲化向量
    auto blind_witness = blinding_commitment.commit(prover_state, blind_refs);

    return ZkWitness<F>{
        std::move(f_hat_vectors), std::move(f_hat_witnesses),
        std::move(blind_polys), std::move(blind_vectors), std::move(blind_witness)};
}

// ============================================================================
// ZkConfig::receive_commitments() — 接收 ZK 承诺（验证者端）
//
// verifier_state — transcript
// num_polys      — 多项式数量
//
// 接收 num_polys 个 f_hat WHIR 承诺 + 1 个 blinding WHIR 承诺
// 返回 ZkCommitment
// ============================================================================

template <typename F>
template <typename Transcript>
ZkCommitment<F> ZkConfig<F>::receive_commitments(
    Transcript& verifier_state, std::size_t num_polys) const
{
    std::vector<::whir::protocols::whir::Commitment<F>> f_hat;
    f_hat.reserve(num_polys);
    for (std::size_t i = 0; i < num_polys; ++i)
        f_hat.push_back(blinded_commitment.receive_commitment(verifier_state));
    auto blind = blinding_commitment.receive_commitment(verifier_state);
    return {std::move(f_hat), std::move(blind)};
}

// ============================================================================
// ZkConfig::prove() — ZK WHIR 完整证明（11 步）
//
// prover_state — Fiat-Shamir transcript
// vectors_flat — 原始多项式系数（展平）
// witness      — commit() 产生的 ZkWitness
// linear_forms — 约束线性形式
// evaluations  — 声明的求值
// rng          — RNG
//
// 返回 whir::FinalClaim<F>（evaluation_point + RLC 系数）
//
// 步骤:
//   1. blinding_challenge（beta，从 transcript 获取）
//   2. 折叠权重到 mask 周期，计算 M(gamma, -rho) 求值，发送
//   3. masking_challenge（rho，必须非零）
//   4. modified_evaluations = original_eval + M_eval（零知识掩盖）
//   5. 开启 f_hat 初始域内
//   6. 挤压 tau1, tau2（STIR 合并参数）
//   7. 展开 h_gammas = all_gammas(in_domain_points)，在 gamma 块上求值
//   8. 逐 gamma: 发送 (m_eval, g_hat_evals)，累积 m_claims 和 g_hat_claims
//   9. 合并声明: combined_claim + build_combined_and_subproof_claims
//  10. 内部 witness 侧 WHIR 证明（f_hat + modified_evaluations）
//  11. 内部 blinding 侧 WHIR 证明（beq_weights + w_folded_weights）
// ============================================================================

template <typename F>
template <typename Transcript, typename Rng>
::whir::protocols::whir::FinalClaim<F> ZkConfig<F>::prove(
    Transcript& prover_state,
    std::span<const F> vectors_flat,
    ZkWitness<F> witness,
    std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> linear_forms,
    std::span<const F> evaluations,
    Rng& rng) const
{
    (void)vectors_flat;
    (void)rng;
    std::size_t num_polys = witness.f_hat_vectors.size();
    std::size_t num_wit_vars = num_witness_variables();
    std::size_t num_blind_vars = num_blinding_variables();
    std::size_t num_wit_plus_1 = num_wit_vars + 1;

    auto f_hat_vectors = std::move(witness.f_hat_vectors);
    auto f_hat_witnesses = std::move(witness.f_hat_witnesses);
    auto blinding_polys = std::move(witness.blinding_polynomials);
    auto blinding_vectors = std::move(witness.blinding_vectors);
    auto blinding_witness = std::move(witness.blinding_witness);

    Embedding identity;

    // ---- 步骤 1: blinding_challenge ----
    // beta: 用于在 gamma 块求值中组合 g_hat 求值
    F blinding_challenge = prover_state.template verifier_message<F>();

    // ---- 步骤 2: 折叠权重并计算 M(gamma, -rho) 求值 ----
    // 对每个线性形式权重:
    //   w_folded = fold_weight_to_mask_size(weight, num_wit_vars, num_blind_vars)
    //   对每个多项式 pi 和变量 v:
    //     m_eval = <w_folded, blinding_vector[pi][v=0]>
    //
    // 输出:
    //   w_folded_weights           — 用于 blinding 侧 WHIR
    //   m_evals                    — 用于掩盖原始求值
    //   w_folded_blinding_evals    — 发送给验证者
    std::vector<::whir::algebra::Covector<F>> w_folded_weights;
    std::vector<F> m_evals;
    std::vector<F> w_folded_blinding_evals;

    w_folded_weights.reserve(linear_forms.size());
    m_evals.reserve(evaluations.size());
    w_folded_blinding_evals.reserve(linear_forms.size() * num_polys * num_wit_plus_1);

    for (const auto& weight : linear_forms) {
        auto folded_vec = fold_weight_to_mask_size<F>(*weight, num_wit_vars, num_blind_vars);
        auto w_folded = ::whir::algebra::Covector<F>(std::move(folded_vec));

        for (std::size_t pi = 0; pi < num_polys; ++pi) {
            std::size_t base = pi * num_wit_plus_1;
            for (std::size_t v = 0; v < num_wit_plus_1; ++v) {
                F eval = w_folded.evaluate(identity, blinding_vectors[base + v]);
                w_folded_blinding_evals.push_back(eval);
                if (v == 0) m_evals.push_back(eval); // M(gamma, -rho) = 分量 0
            }
        }
        w_folded_weights.push_back(std::move(w_folded));
    }

    // 发送所有 w_folded_blinding_evals
    for (const auto& eval : w_folded_blinding_evals)
        prover_state.prover_message(eval);

    // ---- 步骤 3: masking_challenge (rho) ----
    // rho != 0 确保非平凡掩盖
    F masking_challenge = prover_state.template verifier_message<F>();
    assert(masking_challenge != F::zero());

    // ---- 步骤 4: 构造 modified_evaluations ----
    // modified_eval[i] = eval[i] + m_eval[i]（零知识掩盖）
    std::vector<F> modified_evaluations(evaluations.size());
    for (std::size_t i = 0; i < evaluations.size(); ++i)
        modified_evaluations[i] = evaluations[i] + m_evals[i];

    // ---- 步骤 5: 开启 f_hat 初始域内 ----
    std::vector<const ::whir::protocols::irs_commit::Witness<F, F>*> witness_ptrs;
    witness_ptrs.reserve(f_hat_witnesses.size());
    for (const auto& w : f_hat_witnesses) witness_ptrs.push_back(&w);

    auto initial_in_domain = blinded_commitment.initial_committer.open(prover_state, witness_ptrs);

    // ---- 步骤 6: tau1, tau2 ----
    // tau1: 合并 (m_claim, g_hat_claims) 的随机标量
    // tau2: 批量处理 gamma 求值的随机标量
    F tau1 = prover_state.template verifier_message<F>();
    F tau2 = prover_state.template verifier_message<F>();

    // ---- 步骤 7: h_gammas + gamma 块求值 ----
    // 将每个域内挑战点展开为其陪集 gamma 点
    auto h_gammas = all_gammas(initial_in_domain.points);
    std::size_t num_gammas = h_gammas.size();

    // 在所有 gamma 点上求值盲化多项式，累积 beq 权重
    auto [eval_results, beq_weight_accum] = evaluate_gamma_block<F>(
        blinding_polys, h_gammas, masking_challenge, blinding_challenge, tau2,
        num_blind_vars, num_wit_vars);

    // ---- 步骤 8: 发送逐 gamma 值，累积声明 ----
    std::size_t stride_per_poly = num_wit_vars + 2;
    std::size_t stride_per_gamma = num_polys * stride_per_poly;

    std::vector<F> m_claims(num_polys, F::zero());
    std::vector<F> g_hat_claims(num_polys * num_wit_vars, F::zero());
    std::vector<F> batched_h_claims(num_polys, F::zero());

    {
        F tau2_pow = F::one();
        for (std::size_t gi = 0; gi < num_gammas; ++gi) {
            const F* base_ptr = eval_results.data() + gi * stride_per_gamma;
            for (std::size_t pi = 0; pi < num_polys; ++pi) {
                const F* off = base_ptr + pi * stride_per_poly;
                F m_eval = off[0];
                prover_state.prover_message(m_eval);
                for (std::size_t j = 0; j < num_wit_vars; ++j)
                    prover_state.prover_message(off[1 + j]);

                // 累积: 每个声明按 tau2^gi 加权
                m_claims[pi] += tau2_pow * m_eval;
                for (std::size_t j = 0; j < num_wit_vars; ++j)
                    g_hat_claims[pi * num_wit_vars + j] += tau2_pow * off[1 + j];
                batched_h_claims[pi] += tau2_pow * off[1 + num_wit_vars];
            }
            tau2_pow *= tau2;
        }
    }

    // ---- 步骤 9: 合并声明 ----
    // combined_claims[i] = m_claims[i] + 2*tau1 * SUM_j tau1^j * g_hat_claims[i][j]
    // subproof_claims: 展平的 [m_claims, g_hat_claims...] 用于 blinding 侧 WHIR
    std::vector<std::span<const F>> g_hat_slices(num_polys);
    for (std::size_t i = 0; i < num_polys; ++i)
        g_hat_slices[i] = std::span{g_hat_claims}.subspan(i * num_wit_vars, num_wit_vars);

    auto [combined_claims, batched_blind_subproof_claims] =
        build_combined_and_subproof_claims<F>(std::span<const F>{m_claims}, g_hat_slices, tau1);

    for (const auto& c : combined_claims) prover_state.prover_message(c);
    for (const auto& c : batched_h_claims) prover_state.prover_message(c);

    // ---- 步骤 10: 内部 witness 侧 WHIR 证明 ----
    // 对 f_hat 向量 + modified_evaluations 运行标准 WHIR 证明
    std::vector<std::span<const F>> f_hat_spans;
    f_hat_spans.reserve(f_hat_vectors.size());
    for (const auto& v : f_hat_vectors) f_hat_spans.push_back(v);

    std::vector<::whir::protocols::irs_commit::Witness<F, F>> whir_witnesses;
    whir_witnesses.reserve(f_hat_witnesses.size());
    for (auto& w : f_hat_witnesses) whir_witnesses.push_back(std::move(w));

    auto result = blinded_commitment.prove(
        prover_state, f_hat_spans,
        std::span<const ::whir::protocols::irs_commit::Witness<F, F>>{whir_witnesses},
        std::move(linear_forms), modified_evaluations);

    // ---- 步骤 11: 内部 blinding 侧 WHIR 证明 ----
    // blinding_forms = [beq_weights, w_folded_weights[0], ..., w_folded_weights[n-1]]
    // all_blinding_claims = [batched_blind_subproof_claims, w_folded_blinding_evals]

    auto beq_weights = ::whir::algebra::Covector<F>(std::move(beq_weight_accum));

    std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> blinding_forms;
    blinding_forms.push_back(std::make_unique<::whir::algebra::Covector<F>>(std::move(beq_weights)));
    for (auto& wf : w_folded_weights)
        blinding_forms.push_back(std::make_unique<::whir::algebra::Covector<F>>(std::move(wf)));

    std::vector<F> all_blinding_claims;
    all_blinding_claims.insert(all_blinding_claims.end(),
        batched_blind_subproof_claims.begin(), batched_blind_subproof_claims.end());
    all_blinding_claims.insert(all_blinding_claims.end(),
        w_folded_blinding_evals.begin(), w_folded_blinding_evals.end());

    std::vector<std::span<const F>> blind_vec_spans;
    blind_vec_spans.reserve(blinding_vectors.size());
    for (const auto& v : blinding_vectors) blind_vec_spans.push_back(v);

    std::vector<::whir::protocols::irs_commit::Witness<F, F>> blind_wits;
    blind_wits.push_back(std::move(blinding_witness));

    blinding_commitment.prove(prover_state, blind_vec_spans,
        std::span<const ::whir::protocols::irs_commit::Witness<F, F>>{blind_wits},
        std::move(blinding_forms), all_blinding_claims);

    return result;
}

// ============================================================================
// ZkConfig::verify() — ZK WHIR 完整验证（9 步）
//
// verifier_state — Fiat-Shamir transcript
// weights        — 线性形式指针
// evaluations    — 声明的求值
// commitment     — receive_commitments() 产生的 ZkCommitment
//
// 返回 true 接受，false 拒绝
//
// 步骤:
//   1. blinding_challenge（确定性，与证明者一致）
//   2. 读取 w_folded_blinding_evals，提取 m_evals
//   3. masking_challenge（rho，必须非零）
//   4. 验证 f_hat 初始域内（Merkle 路径验证）
//   5. tau1, tau2 + h_gammas 展开
//   6. 读取逐 gamma 值，累积 m_claims/g_hat_claims，
//      本地计算 expected_batched_h_claims
//   7. 读取合并声明，与本地计算的期望值比较
//   8. 验证 witness 侧 WHIR（f_hat + modified_evaluations）
//   9. 验证 blinding 侧 WHIR（beq_weights + w_folded_weights）
// ============================================================================

template <typename F>
template <typename Transcript>
bool ZkConfig<F>::verify(
    Transcript& verifier_state,
    std::span<const ::whir::algebra::LinearForm<F>*> weights,
    std::span<const F> evaluations,
    const ZkCommitment<F>& commitment) const
{
    std::size_t num_polys = commitment.f_hat.size();
    std::size_t num_wit_vars = num_witness_variables();
    std::size_t num_blind_vars = num_blinding_variables();
    std::size_t num_wit_plus_1 = num_wit_vars + 1;

    // ---- 步骤 1: blinding_challenge（与证明者确定性一致） ----
    F blinding_challenge = verifier_state.template verifier_message<F>();

    // ---- 步骤 2: 读取 w_folded_blinding_evals，提取 m_evals ----
    // 布局: 每个权重 x 每个多项式 x (num_wit_vars+1) 个域元素
    std::size_t num_w_folded = weights.size() * num_polys * num_wit_plus_1;
    std::vector<F> w_folded_blinding_evals(num_w_folded);
    for (auto& val : w_folded_blinding_evals)
        if (!verifier_state.prover_message(val)) return false;

    // 提取 m_evals（每组 num_wit_plus_1 的第一个元素）
    std::vector<F> m_evals;
    for (std::size_t i = 0; i < w_folded_blinding_evals.size(); i += num_wit_plus_1)
        m_evals.push_back(w_folded_blinding_evals[i]);

    // ---- 步骤 3: masking_challenge（必须非零） ----
    F masking_challenge = verifier_state.template verifier_message<F>();
    if (masking_challenge == F::zero()) return false;

    // ---- 步骤 4: 验证 f_hat 初始域内 ----
    std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> cptrs;
    cptrs.reserve(commitment.f_hat.size());
    for (const auto& c : commitment.f_hat) cptrs.push_back(&c);

    auto initial_in_domain = blinded_commitment.initial_committer.verify(verifier_state, cptrs);
    if (initial_in_domain.points.empty() &&
        blinded_commitment.initial_committer.in_domain_samples != 0) return false;

    // ---- 步骤 5: tau1, tau2 + h_gammas ----
    auto h_gammas = all_gammas(initial_in_domain.points);
    F tau1 = verifier_state.template verifier_message<F>();
    F tau2 = verifier_state.template verifier_message<F>();

    // ---- 步骤 6: 读取逐 gamma 值，累积声明 ----
    // 验证者本地计算 expected_batched_h_claims 用于后续比较
    std::vector<F> m_claims(num_polys, F::zero());
    std::vector<std::vector<F>> g_hat_claims_per_poly(num_polys,
        std::vector<F>(num_wit_vars, F::zero()));
    std::vector<F> expected_batched_h_claims(num_polys, F::zero());

    F tau2_power = F::one();
    for (const auto& gamma : h_gammas) {
        for (std::size_t pi = 0; pi < num_polys; ++pi) {
            F m_eval;
            if (!verifier_state.prover_message(m_eval)) return false;

            // 重构 h_value = m_eval + SUM_j beta^j * gamma^(2^(j-1)) * g_hat_eval_j
            F h_value = m_eval;
            F blind_pow = blinding_challenge;
            F gamma_pow = gamma;
            m_claims[pi] += tau2_power * m_eval;

            for (std::size_t j = 0; j < num_wit_vars; ++j) {
                F g_hat_eval;
                if (!verifier_state.prover_message(g_hat_eval)) return false;
                g_hat_claims_per_poly[pi][j] += tau2_power * g_hat_eval;
                h_value += blind_pow * gamma_pow * g_hat_eval;
                blind_pow *= blinding_challenge;
                gamma_pow = gamma_pow.square();
            }
            expected_batched_h_claims[pi] += tau2_power * h_value;
        }
        tau2_power *= tau2;
    }

    // ---- 步骤 7: 读取合并声明并验证 ----
    std::vector<F> combined_claims(num_polys);
    for (auto& c : combined_claims)
        if (!verifier_state.prover_message(c)) return false;
    std::vector<F> batched_h_claims(num_polys);
    for (auto& c : batched_h_claims)
        if (!verifier_state.prover_message(c)) return false;

    // 比较证明者发送的 batched_h_claims 与本地计算的期望值
    if (batched_h_claims != expected_batched_h_claims) return false;

    // 验证 combined_claims
    std::vector<std::span<const F>> g_hat_slices(num_polys);
    for (std::size_t i = 0; i < num_polys; ++i)
        g_hat_slices[i] = g_hat_claims_per_poly[i];

    auto [expected_combined, expected_blind_subproof] =
        build_combined_and_subproof_claims<F>(m_claims, g_hat_slices, tau1);

    if (combined_claims != expected_combined) return false;

    // ---- 步骤 8: 验证 witness 侧 WHIR ----
    // modified_evaluations = eval + m_eval（零知识掩盖）
    std::vector<F> modified_evaluations(evaluations.size());
    for (std::size_t i = 0; i < evaluations.size(); ++i)
        modified_evaluations[i] = evaluations[i] + m_evals[i % m_evals.size()];

    auto fc = blinded_commitment.verify(verifier_state, cptrs, modified_evaluations);
    if (!fc.verify(std::vector<const ::whir::algebra::LinearForm<F>*>{weights.begin(), weights.end()}))
        return false;

    // ---- 步骤 9: 验证 blinding 侧 WHIR ----
    // 本地构造 beq 权重 + w_folded 权重，与证明者的声明验证

    // 从 gamma 批量构造 beq_cv
    auto beq_cv = construct_batched_eq_weights_from_gammas<F>(
        h_gammas, masking_challenge, tau2, num_blind_vars);

    // 将每个线性形式折叠到 mask 周期
    std::vector<::whir::algebra::Covector<F>> w_folded_cvs;
    w_folded_cvs.reserve(weights.size());
    for (const auto* w : weights) {
        auto folded = fold_weight_to_mask_size<F>(*w, num_wit_vars, num_blind_vars);
        w_folded_cvs.emplace_back(std::move(folded));
    }

    // blinding_forms = [beq_weights, w_folded_weights...]
    std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> blinding_forms;
    blinding_forms.push_back(std::make_unique<::whir::algebra::Covector<F>>(std::move(beq_cv)));
    for (auto& wf : w_folded_cvs)
        blinding_forms.push_back(std::make_unique<::whir::algebra::Covector<F>>(std::move(wf)));

    // all_expected_blinding = [expected_blind_subproof, w_folded_blinding_evals]
    std::vector<F> all_expected_blinding;
    all_expected_blinding.insert(all_expected_blinding.end(),
        expected_blind_subproof.begin(), expected_blind_subproof.end());
    all_expected_blinding.insert(all_expected_blinding.end(),
        w_folded_blinding_evals.begin(), w_folded_blinding_evals.end());

    std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> blind_cptrs{&commitment.blinding};
    auto blind_fc = blinding_commitment.verify(verifier_state, blind_cptrs, all_expected_blinding);

    // 验证 FinalClaim
    std::vector<const ::whir::algebra::LinearForm<F>*> blind_lf_ptrs;
    blind_lf_ptrs.reserve(blinding_forms.size());
    for (const auto& bf : blinding_forms) blind_lf_ptrs.push_back(bf.get());

    return blind_fc.verify(blind_lf_ptrs);
}

} // namespace whir::protocols::whir_zk
