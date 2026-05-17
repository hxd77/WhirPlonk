#pragma once

// =============================================================================
// whir_verifier.hpp — WHIR 验证者完整实现。
// 对应 WHIR 中的 src/protocols/whir/verifier.rs。
//
// 定义 Config<M>::verify() 模板成员函数 — 12 步 WHIR 验证流程。
//
// 此文件由 whir.hpp 在末尾 include, 不要单独 #include。
// =============================================================================

#include "../geometric_challenge.hpp"
#include "../../algebra/linear_form.hpp"
#include "../../algebra/multilinear.hpp"
#include "../../algebra/sumcheck.hpp"
#include "../../algebra/ntt/utils.hpp"
#include "../../algebra/utilities.hpp"
#include "../../hash/blake3_engine.hpp"
#include "../../hash/sha2_engine.hpp"
#include "../../utils.hpp"

#include <cassert>
#include <deque>
#include <span>
#include <utility>
#include <vector>

namespace whir::protocols::whir {

// =============================================================================
// Config<M>::verify() — WHIR 完整验证 (12 步)。
//
// 输入:
//   verifier_state  — VerifierState (含 proof 的 Fiat-Shamir transcript)
//   commitments_ptr — receive_commitment() 返回的 Commitment 指针列表
//   evaluations     — 声明的求值结果 (布局与 prover 侧相同)
//
// 输出: FinalClaim<Target>
//       - evaluation_point: 所有 sumcheck 轮坐标的拼接
//       - rlc_coefficients: 初始约束 RLC 系数
//       - linear_form_rlc: 从 sumcheck 不变式恢复的 RLC 求值
//
// 12 步流程:
//   1. 读取补全的 OOD 评价值 (prover 在步骤 1 发送的额外求值)
//   2. 向量的 RLC (与 prover 相同的确定性等比数列)
//   3. 约束的 RLC (与 prover 相同)
//   4. 计算 "The Sum" (与 prover 相同的公式)
//   5. 初始 sumcheck 验证
//   6. 逐轮验证:
//      a) 接收承诺 (IRS receive_commitment)
//      b) 验证 PoW
//      c) 验证前一轮打开 (Merkle 路径验证)
//      d) STIR RLC + 约束收集
//      e) STIR sumcheck 验证
//   7. 读取最终向量
//   8. 验证最终 PoW
//   9. 验证最终 in-domain (本地检查求值一致性)
//  10. 最终 sumcheck 验证
//  11. 汇总求值点 (拼接所有 sumcheck 的 coords)
//  12. 从 sumcheck 不变式恢复 linear_form_rlc
// =============================================================================

template <typename M>
template <typename Transcript>
FinalClaim<typename M::Target> Config<M>::verify(
    Transcript& verifier_state,
    std::span<const irs_commit::Commitment<Target>*> commitments_ptr,
    std::span<const Target> evaluations) const
{
    using F = Target;
    // 推断向量数和约束数
    const std::size_t num_vectors = commitments_ptr.size() * initial_committer.num_vectors;
    const std::size_t num_linear_forms = num_vectors > 0
        ? evaluations.size() / num_vectors : 0;

    if (num_vectors == 0) return FinalClaim<F>{};

    ::whir::hash::Blake3 blake3_pow_engine;
    ::whir::hash::Sha2 sha2_pow_engine;
    auto pow_engine_lookup =
        [&blake3_pow_engine, &sha2_pow_engine](::whir::EngineId id)
            -> const ::whir::hash::HashEngine& {
        if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_pow_engine;
        return blake3_pow_engine;
    };

    // ==========================================================================
    // 步骤 1: 读取补全的 OOD 评价值。
    //
    // 与 prover 步骤 1 对称:
    //   - 对每个 witness, 先从已有数据中取 OOD 值
    //   - 对于不在当前 commitment 中的向量, 从 transcript 读取 prover 发送的额外求值
    //
    // 输入: commitments_ptr[].out_of_domain
    // 输出: oods_evals  — UnivariateEvaluation 列表
    //       oods_matrix — 完整域外求值矩阵
    //
    // 安全要点: verifier 必须确保读取的 OOD 值与承诺一致,
    //          否则 prover 可能发送不一致的域外求值来骗过验证。
    //          这通过后续的域内挑战 + Merkle 验证来保证。
    // ==========================================================================
    std::vector<::whir::algebra::UnivariateEvaluation<F>> oods_evals;
    std::vector<F> oods_matrix;
    {
        std::size_t vector_offset = 0;
        for (const auto* commitment : commitments_ptr) {
            auto c_evals = commitment->out_of_domain.evaluators(initial_size());
            std::size_t c_cols = commitment->out_of_domain.num_columns();

            for (std::size_t ei = 0; ei < c_evals.size(); ++ei) {
                for (std::size_t j = 0; j < num_vectors; ++j) {
                    if (j >= vector_offset && j < c_cols + vector_offset) {
                        // 当前 commitment 包含此向量 → 直接取
                        oods_matrix.push_back(
                            commitment->out_of_domain.matrix[ei * c_cols + (j - vector_offset)]);
                    } else {
                        // 当前 commitment 不包含 → 从 transcript 读取
                        F val;
                        if (!verifier_state.prover_message(val)) return FinalClaim<F>{};
                        oods_matrix.push_back(val);
                    }
                }
                oods_evals.push_back(c_evals[ei]);
            }
            vector_offset += commitment->num_vectors();
        }
    }

    // ==========================================================================
    // 步骤 2: 向量的 RLC (与 prover 确定性一致)。
    //
    // geometric_challenge 保证 verifier 挤出与 prover 相同的等比数列,
    // 因为 transcript (sponge) 状态完全相同。
    //
    // 输入: (无, 由 transcript 挤出)
    // 输出: vector_rlc_coeffs — 长度为 num_vectors 的等比数列, [0]==1
    // ==========================================================================
    auto vector_rlc_coeffs = geometric_challenge<F>(verifier_state, num_vectors);

    // ==========================================================================
    // 步骤 3: 约束的 RLC (与 prover 确定性一致)。
    //
    // 输入: (无)
    // 输出: constraint_rlc_coeffs — 长度 = num_linear_forms + oods_evals.size()
    //       initial_forms_rlc     — [0..num_linear_forms) 的 span
    //       oods_rlc              — [num_linear_forms..) 的 span
    // ==========================================================================
    auto constraint_rlc_coeffs = geometric_challenge<F>(verifier_state,
        num_linear_forms + oods_evals.size());
    std::span<const F> initial_forms_rlc(constraint_rlc_coeffs.data(), num_linear_forms);
    std::span<const F> oods_rlc(std::span{constraint_rlc_coeffs}.subspan(num_linear_forms));

    // ==========================================================================
    // 步骤 4: 计算 "The Sum" (与 prover 步骤 4 对称)。
    //
    // the_sum = Σ_i constraint_rlc[i] * (Σ_j vector_rlc[j] * eval[i][j])
    //          + Σ_i oods_rlc[i]   * (Σ_j vector_rlc[j] * ood_matrix[i][j])
    //
    // 输出: the_sum — 初始 sumcheck 的目标值
    // ==========================================================================
    F the_sum = F::zero();

    // 初始约束部分
    for (std::size_t i = 0; i < num_linear_forms; ++i) {
        F row_sum = F::zero();
        for (std::size_t j = 0; j < num_vectors; ++j)
            row_sum += vector_rlc_coeffs[j] * evaluations[i * num_vectors + j];
        the_sum += constraint_rlc_coeffs[i] * row_sum;
    }

    // 域外约束部分
    for (std::size_t i = 0; i < oods_rlc.size(); ++i) {
        F row_sum = F::zero();
        for (std::size_t j = 0; j < num_vectors; ++j)
            row_sum += vector_rlc_coeffs[j] * oods_matrix[i * num_vectors + j];
        the_sum += oods_rlc[i] * row_sum;
    }

    // 保存约束用于最后恢复 linear_form_rlc (步骤 12)
    std::vector<std::pair<std::vector<F>,
        std::vector<::whir::algebra::UnivariateEvaluation<F>>>> round_constraints;
    round_constraints.emplace_back(
        std::vector<F>(oods_rlc.begin(), oods_rlc.end()), std::move(oods_evals));

    // ==========================================================================
    // 步骤 5: 初始 sumcheck 验证。
    //
    // 如有约束: 运行 sumcheck.verify() 验证 ⟨vector, covector⟩ = the_sum
    //           返回折叠坐标 fr. 注意 verifier 没有 vector 和 covector,
    //           但 sumcheck 协议保证: 如果 prover 作弊, 验证会以高概率失败。
    //
    // 如无约束: 直接从 transcript 读折叠坐标, 验证跳过 PoW。
    //
    // 输出: round_fr — MultilinearPoint 列表 (每轮 sumcheck 一个)
    // ==========================================================================
    std::vector<::whir::algebra::MultilinearPoint<F>> round_fr;
    bool is_first_round = true;

    {
        ::whir::algebra::MultilinearPoint<F> fr;
        if (constraint_rlc_coeffs.empty()) {
            // 无约束: 读坐标 → 验证 PoW
            auto fr_vec = verifier_state.template verifier_message_vec<F>(initial_sumcheck.num_rounds);
            if (!initial_skip_pow.verify(verifier_state, pow_engine_lookup)) return FinalClaim<F>{};
            fr = ::whir::algebra::MultilinearPoint<F>{std::move(fr_vec)};
        } else {
            // 有约束: 正常 sumcheck 验证
            fr = initial_sumcheck.verify(verifier_state, the_sum);
        }
        round_fr.push_back(std::move(fr));
    }

    // ==========================================================================
    // 步骤 6: 逐轮验证 (与 prover 步骤 6 对称)。
    //
    // 每轮:
    //   6a. 接收新承诺 (IRS receive_commitment)
    //   6b. 验证 PoW
    //   6c. 验证前一轮打开 (Merkle 路径验证)
    //       - 首轮: 用 initial_committer.verify() 验证多个 commitment
    //       - 后续: 用 prev_rc.irs_committer.verify() 验证单个
    //   6d. STIR RLC + 约束收集
    //   6e. STIR sumcheck 验证
    //
    // 安全关键: 步骤 6c 的 Merkle 验证确保 prover 打开的域内值
    //          确实来自 commit 时承诺的编码矩阵行。
    // ==========================================================================
    const irs_commit::Commitment<F>* prev_round_commitment = nullptr;

    // 持久化所有 round 的 commitment, 避免悬空指针。
    // Rust 侧通过 RoundCommitment enum 持有所有权, C++ 用 deque 保证指针稳定。
    std::deque<irs_commit::Commitment<F>> stored_commitments;

    for (std::size_t round_idx = 0; round_idx < round_configs.size(); ++round_idx) {
        const auto& rc = round_configs[round_idx];

        // --- 6a. 接收承诺 ---
        // receive_commitment 内部:
        //   1. 接收 Merkle root (通过 transcript)
        //   2. 挤出域外采样点 (确定性, 与 prover 相同)
        //   3. 接收域外求值
        auto commitment = rc.irs_committer.receive_commitment(verifier_state);

        // --- 6b. 验证 PoW ---
        // 检查 prover 发送的 nonce 是否满足难度要求
        if (!rc.pow.verify(verifier_state, pow_engine_lookup)) return FinalClaim<F>{};

        // --- 6c. 验证前一轮打开 ---
        irs_commit::Evaluations<F> in_domain;
        std::vector<F> poly_rlc;
        if (is_first_round) {
            // 首轮: 验证 initial_committer 的多个 commitment
            auto in_domain_src = initial_committer.verify(verifier_state, commitments_ptr);
            in_domain = in_domain_src.template lift<M>(*embedding());
            poly_rlc = vector_rlc_coeffs;
            is_first_round = false;
        } else {
            // 后续轮: 验证上一轮的单个 commitment
            auto& prev_rc = round_configs[round_idx - 1];
            std::vector<const irs_commit::Commitment<F>*> cptrs{prev_round_commitment};
            in_domain = prev_rc.irs_committer.verify(verifier_state, cptrs);
            poly_rlc = {F::one()};
        }

        // --- 6d. STIR RLC + 约束收集 ---
        auto constraint_weights = commitment.out_of_domain.evaluators(rc.sumcheck.initial_size);
        auto in_domain_evals = in_domain.evaluators(rc.sumcheck.initial_size);
        constraint_weights.insert(constraint_weights.end(), in_domain_evals.begin(), in_domain_evals.end());

        // STIR 评价值
        F one_val = F::one();
        auto constraint_values = commitment.out_of_domain.values(std::span<const F>{&one_val, 1});
        auto& last_fr = round_fr.back();
        auto eq_w = last_fr.coords.size() > 0 ? last_fr.eq_weights() : std::vector<F>{F::one()};
        auto tp = ::whir::algebra::tensor_product<F>(poly_rlc, eq_w);
        auto in_domain_vals = in_domain.values(tp);
        constraint_values.insert(constraint_values.end(), in_domain_vals.begin(), in_domain_vals.end());

        // STIR RLC (geometric challenge)
        auto constraint_rlc = geometric_challenge<F>(verifier_state, constraint_values.size());
        the_sum += ::whir::algebra::dot<F>(constraint_rlc, constraint_values);
        round_constraints.emplace_back(std::move(constraint_rlc), std::move(constraint_weights));

        // --- 6e. STIR sumcheck 验证 ---
        auto fr = rc.sumcheck.verify(verifier_state, the_sum);
        round_fr.push_back(std::move(fr));

        // 持久化 commitment 为下一轮
        stored_commitments.push_back(std::move(commitment));
        prev_round_commitment = &stored_commitments.back();
    }

    // ==========================================================================
    // 步骤 7: 读取最终向量。
    //
    // 从 transcript 读取 prover 在步骤 7 发送的折叠后向量系数。
    // 向量长度 = final_sumcheck.initial_size。
    // ==========================================================================
    std::vector<F> final_vector(final_sumcheck.initial_size);
    for (auto& coeff : final_vector) {
        if (!verifier_state.prover_message(coeff)) return FinalClaim<F>{};
    }

    // ==========================================================================
    // 步骤 8: 验证最终 PoW。
    // ==========================================================================
    {
        if (!final_pow.verify(verifier_state, pow_engine_lookup)) return FinalClaim<F>{};
    }

    // ==========================================================================
    // 步骤 9: 验证最终 in-domain。
    //
    // 本地验证: 用 verifier 持有的 final_vector 和 in-domain 求值器
    // 检查 prover 打开的域内值是否与 final_vector 一致。
    //
    // 这步确保: 如果 prover 的 final_vector 不对, 则会与打开的域内求值矛盾。
    // ==========================================================================
    {
        irs_commit::Evaluations<F> in_domain;
        std::vector<F> poly_rlc;
        if (is_first_round) {
            auto in_domain_src = initial_committer.verify(verifier_state, commitments_ptr);
            in_domain = in_domain_src.template lift<M>(*embedding());
            poly_rlc = vector_rlc_coeffs;
        } else {
            auto& prev_rc = round_configs.back();
            std::vector<const irs_commit::Commitment<F>*> cptrs{prev_round_commitment};
            in_domain = prev_rc.irs_committer.verify(verifier_state, cptrs);
            poly_rlc = {F::one()};
        }

        // 构造 in-domain 约束: 对每个求值器, 计算其期待值并断言与打开值一致
        auto weights_iter = in_domain.evaluators(final_vector.size());
        auto& last_fr = round_fr.back();
        auto eq_w = last_fr.coords.size() > 0 ? last_fr.eq_weights() : std::vector<F>{F::one()};
        auto tp = ::whir::algebra::tensor_product<F>(poly_rlc, eq_w);
        auto vals = in_domain.values(tp);

        for (std::size_t i = 0; i < weights_iter.size() && i < vals.size(); ++i) {
            ::whir::algebra::Identity<F> identity;
            F expected = weights_iter[i].evaluate(identity, final_vector);
            if (expected != vals[i]) return FinalClaim<F>{};  // prover 作弊
        }
    }

    // ==========================================================================
    // 步骤 10: 最终 sumcheck 验证。
    //
    // 验证最后一轮折叠后 ⟨final_vector, covector⟩ = the_sum。
    // 返回的 coords 追加到求值点末尾。
    // ==========================================================================
    auto final_fr = final_sumcheck.verify(verifier_state, the_sum);
    round_fr.push_back(std::move(final_fr));

    // ==========================================================================
    // 步骤 11: 汇总求值点。
    //
    // 把所有 sumcheck 轮返回的坐标拼接成一个完整的 evaluation_point。
    // ==========================================================================
    std::vector<F> evaluation_point;
    for (const auto& mp : round_fr)
        evaluation_point.insert(evaluation_point.end(), mp.coords.begin(), mp.coords.end());

    // ==========================================================================
    // 步骤 12: 从 sumcheck 不变式恢复 linear_form_rlc。
    //
    // WHIR 的核心不变量:
    //   final_poly(evaluation_point) * linear_form_rlc = the_sum
    //   其中 final_poly 是最后一轮 sumcheck 发送的多项式。
    //
    // 恢复公式:
    //   linear_form_rlc = the_sum / final_poly(final_vector)
    //
    // 然后逐轮减去每轮的约束贡献 (OOD + STIR):
    //   linear_form_rlc -= Σ weights_rlc[i] * weights[i].mle_evaluate(eval_point_slice)
    //
    // 最终得到的 linear_form_rlc 就是初始约束 RLC 在 evaluation_point 处的值,
    // verifier 可以调用 FinalClaim.verify(linear_forms) 做本地检查。
    // ==========================================================================

    // 用最终 sumcheck 的多项式构造 MLE
    ::whir::algebra::MultilinearExtension<F> poly_mle(
        std::vector<F>(round_fr.back().coords));
    F poly_eval = poly_mle.evaluate(::whir::algebra::Identity<F>{}, final_vector);
    F linear_form_rlc = the_sum;
    // 除以 poly_eval (仅在非零时)
    if (poly_eval != F::zero()) {
        linear_form_rlc = linear_form_rlc * poly_eval.inverse();
    }

    // 逐轮减去约束贡献
    for (std::size_t r = 0; r < round_constraints.size(); ++r) {
        const auto& [weights_rlc, weights] = round_constraints[r];
        // 计算当前轮的变量数 (r=0 用 initial, 否则用上一轮的)
        std::size_t num_vars = (r == 0)
            ? static_cast<std::size_t>(::whir::algebra::ntt::trailing_zeros(initial_committer.vector_size))
            : static_cast<std::size_t>(::whir::algebra::ntt::trailing_zeros(
                round_configs[r - 1].irs_committer.vector_size));

        // 取 evaluation_point 的后 num_vars 个坐标
        std::size_t start = evaluation_point.size() >= num_vars
            ? evaluation_point.size() - num_vars : 0;
        std::span<const F> ep_slice{evaluation_point.data() + start, evaluation_point.size() - start};

        for (std::size_t i = 0; i < weights_rlc.size() && i < weights.size(); ++i)
            linear_form_rlc -= weights_rlc[i] * weights[i].mle_evaluate(ep_slice);
    }

    // 返回 FinalClaim, verifier 后续可调用 claim.verify(linear_forms) 做最终检查
    return FinalClaim<F>{
        std::move(evaluation_point),
        std::vector<F>(initial_forms_rlc.begin(), initial_forms_rlc.end()),
        linear_form_rlc,
    };
}

} // namespace whir::protocols::whir
