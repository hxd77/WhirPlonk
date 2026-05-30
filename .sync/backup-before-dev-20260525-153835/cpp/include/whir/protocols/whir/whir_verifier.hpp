#pragma once

// ============================================================================
// whir_verifier.hpp — WHIR 验证者: Config<M>::verify() 实现
//
// 12 步验证流程。由 whir.hpp 在文件末尾包含，不要直接包含。
//
// 对应 Rust 文件: src/protocols/whir/verifier.rs
// ============================================================================

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

// ============================================================================
// Config<M>::verify() — 完整 WHIR 验证（12 步）
//
// verifier_state  — 包含已加载证明的 Fiat-Shamir transcript
// commitments_ptr — receive_commitment() 产生的 Commitment 指针
// evaluations     — 声明的求值（与证明者布局相同）
//
// 返回 FinalClaim<Target>:
//   evaluation_point — 所有 sumcheck 轮坐标的拼接
//   rlc_coefficients — 初始约束 RLC 系数
//   linear_form_rlc  — 从 sumcheck 不变量恢复
//
// 步骤:
//   1. 读取补全的 OOD 求值（证明者在步骤 1 发送缺失部分）
//   2. 向量 RLC（确定性，与证明者相同的几何级数）
//   3. 约束 RLC
//   4. 计算 "The Sum"（与证明者相同公式）
//   5. 初始 sumcheck 验证
//   6. 逐轮: 接收承诺 → PoW 验证 → 开启验证 → STIR RLC → sumcheck 验证
//   7. 读取最终向量
//   8. 验证最终 PoW
//   9. 验证最终域内（本地求值一致性检查）
//  10. 最终 sumcheck 验证
//  11. 拼接所有 sumcheck 坐标为 evaluation_point
//  12. 从 sumcheck 不变量恢复 linear_form_rlc
// ============================================================================

template <typename M>
template <typename Transcript>
FinalClaim<typename M::Target> Config<M>::verify(
    Transcript& verifier_state,
    std::span<const irs_commit::Commitment<Target>*> commitments_ptr,
    std::span<const Target> evaluations) const
{
    using F = Target;
    const std::size_t num_vectors = commitments_ptr.size() * initial_committer.num_vectors;
    const std::size_t num_linear_forms = num_vectors > 0
        ? evaluations.size() / num_vectors : 0;

    if (num_vectors == 0) return FinalClaim<F>::rejected(__LINE__);

    ::whir::hash::Blake3 blake3_pow_engine;
    ::whir::hash::Sha2 sha2_pow_engine;
    auto pow_engine_lookup =
        [&blake3_pow_engine, &sha2_pow_engine](::whir::EngineId id)
            -> const ::whir::hash::HashEngine& {
        if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_pow_engine;
        return blake3_pow_engine;
    };

    // =========================================================================
    // 步骤 1: 读取补全的 OOD 求值
    //
    // 与证明者步骤 1 对称:
    //   - 当前承诺中的向量: 从已有数据读取
    //   - 其他向量: 从 transcript 读取证明者发送的额外求值
    //
    // 安全性: 验证者必须确保与承诺一致；
    //         后续的域内挑战 + Merkle 验证保证此性质
    // =========================================================================
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
                        oods_matrix.push_back(
                            commitment->out_of_domain.matrix[ei * c_cols + (j - vector_offset)]);
                    } else {
                        F val;
                        if (!verifier_state.prover_message(val)) return FinalClaim<F>::rejected(__LINE__);
                        oods_matrix.push_back(val);
                    }
                }
                oods_evals.push_back(c_evals[ei]);
            }
            vector_offset += commitment->num_vectors();
        }
    }

    // =========================================================================
    // 步骤 2: 向量 RLC（确定性，与证明者完全一致）
    // =========================================================================
    auto vector_rlc_coeffs = geometric_challenge<F>(verifier_state, num_vectors);

    // =========================================================================
    // 步骤 3: 约束 RLC（确定性，与证明者完全一致）
    // =========================================================================
    auto constraint_rlc_coeffs = geometric_challenge<F>(verifier_state,
        num_linear_forms + oods_evals.size());
    std::span<const F> initial_forms_rlc(constraint_rlc_coeffs.data(), num_linear_forms);
    std::span<const F> oods_rlc(std::span{constraint_rlc_coeffs}.subspan(num_linear_forms));

    // =========================================================================
    // 步骤 4: 计算 "The Sum"（与证明者步骤 4 对称）
    // =========================================================================
    F the_sum = F::zero();

    for (std::size_t i = 0; i < num_linear_forms; ++i) {
        F row_sum = F::zero();
        for (std::size_t j = 0; j < num_vectors; ++j)
            row_sum += vector_rlc_coeffs[j] * evaluations[i * num_vectors + j];
        the_sum += constraint_rlc_coeffs[i] * row_sum;
    }

    for (std::size_t i = 0; i < oods_rlc.size(); ++i) {
        F row_sum = F::zero();
        for (std::size_t j = 0; j < num_vectors; ++j)
            row_sum += vector_rlc_coeffs[j] * oods_matrix[i * num_vectors + j];
        the_sum += oods_rlc[i] * row_sum;
    }

    // 保存约束用于步骤 12 的 linear_form_rlc 恢复
    std::vector<std::pair<std::vector<F>,
        std::vector<::whir::algebra::UnivariateEvaluation<F>>>> round_constraints;
    round_constraints.emplace_back(
        std::vector<F>(oods_rlc.begin(), oods_rlc.end()), std::move(oods_evals));

    // =========================================================================
    // 步骤 5: 初始 sumcheck 验证
    //
    // 有约束: 运行 sumcheck.verify() — 即使验证者没有 vector/covector，
    //   证明者作弊也会以高概率被检测到
    // 无约束: 直接读取坐标，验证 skip-PoW
    // =========================================================================
    std::vector<::whir::algebra::MultilinearPoint<F>> round_fr;
    bool is_first_round = true;

    {
        ::whir::algebra::MultilinearPoint<F> fr;
        if (constraint_rlc_coeffs.empty()) {
            auto fr_vec = verifier_state.template verifier_message_vec<F>(initial_sumcheck.num_rounds);
            if (!initial_skip_pow.verify(verifier_state, pow_engine_lookup)) return FinalClaim<F>::rejected(__LINE__);
            fr = ::whir::algebra::MultilinearPoint<F>{std::move(fr_vec)};
        } else {
            fr = initial_sumcheck.verify(verifier_state, the_sum);
            if (fr.coords.size() != initial_sumcheck.num_rounds) return FinalClaim<F>::rejected(__LINE__);
        }
        round_fr.push_back(std::move(fr));
    }

    // =========================================================================
    // 步骤 6: 逐轮验证（与证明者步骤 6 对称）
    //
    // 安全关键: 步骤 6c 的 Merkle 验证确保开启的域内值
    // 确实来自承诺的编码矩阵行
    // =========================================================================
    const irs_commit::Commitment<F>* prev_round_commitment = nullptr;

    // 用 deque 存储所有轮承诺以保证指针稳定性
    std::deque<irs_commit::Commitment<F>> stored_commitments;

    for (std::size_t round_idx = 0; round_idx < round_configs.size(); ++round_idx) {
        const auto& rc = round_configs[round_idx];

        // --- 6a. 接收承诺 ---
        // 内部: 接收 Merkle 根，挤压 OOD 点（确定性），接收 OOD 求值
        auto commitment = rc.irs_committer.receive_commitment(verifier_state);

        // --- 6b. 验证 PoW ---
        if (!rc.pow.verify(verifier_state, pow_engine_lookup)) return FinalClaim<F>::rejected(__LINE__);

        // --- 6c. 验证前一轮开启 ---
        irs_commit::Evaluations<F> in_domain;
        std::vector<F> poly_rlc;
        if (is_first_round) {
            auto in_domain_src = initial_committer.verify(verifier_state, commitments_ptr);
            if (in_domain_src.points.size() != initial_committer.in_domain_samples &&
                !initial_committer.deduplicate_in_domain) return FinalClaim<F>::rejected(__LINE__);
            if (in_domain_src.matrix.size() != in_domain_src.points.size()
                * commitments_ptr.size() * initial_committer.num_cols()) return FinalClaim<F>::rejected(__LINE__);
            in_domain = in_domain_src.template lift<M>(*embedding());
            poly_rlc = vector_rlc_coeffs;
            is_first_round = false;
        } else {
            auto& prev_rc = round_configs[round_idx - 1];
            std::vector<const irs_commit::Commitment<F>*> cptrs{prev_round_commitment};
            in_domain = prev_rc.irs_committer.verify(verifier_state, cptrs);
            if (in_domain.points.size() != prev_rc.irs_committer.in_domain_samples &&
                !prev_rc.irs_committer.deduplicate_in_domain) return FinalClaim<F>::rejected(__LINE__);
            if (in_domain.matrix.size() != in_domain.points.size()
                * prev_rc.irs_committer.num_cols()) return FinalClaim<F>::rejected(__LINE__);
            poly_rlc = {F::one()};
        }

        // --- 6d. STIR RLC + 约束收集 ---
        auto constraint_weights = commitment.out_of_domain.evaluators(rc.sumcheck.initial_size);
        auto in_domain_evals = in_domain.evaluators(rc.sumcheck.initial_size);
        constraint_weights.insert(constraint_weights.end(), in_domain_evals.begin(), in_domain_evals.end());

        F one_val = F::one();
        auto constraint_values = commitment.out_of_domain.values(std::span<const F>{&one_val, 1});
        auto& last_fr = round_fr.back();
        auto eq_w = last_fr.coords.size() > 0 ? last_fr.eq_weights() : std::vector<F>{F::one()};
        auto tp = ::whir::algebra::tensor_product<F>(poly_rlc, eq_w);
        auto in_domain_vals = in_domain.values(tp);
        constraint_values.insert(constraint_values.end(), in_domain_vals.begin(), in_domain_vals.end());

        // STIR RLC（几何挑战）
        auto constraint_rlc = geometric_challenge<F>(verifier_state, constraint_values.size());
        the_sum += ::whir::algebra::dot<F>(constraint_rlc, constraint_values);
        round_constraints.emplace_back(std::move(constraint_rlc), std::move(constraint_weights));

        // --- 6e. STIR sumcheck 验证 ---
        auto fr = rc.sumcheck.verify(verifier_state, the_sum);
        if (fr.coords.size() != rc.sumcheck.num_rounds) return FinalClaim<F>::rejected(__LINE__);
        round_fr.push_back(std::move(fr));

        stored_commitments.push_back(std::move(commitment));
        prev_round_commitment = &stored_commitments.back();
    }

    // =========================================================================
    // 步骤 7: 读取最终向量（证明者发送的明文系数）
    // =========================================================================
    std::vector<F> final_vector(final_sumcheck.initial_size);
    for (auto& coeff : final_vector) {
        if (!verifier_state.prover_message(coeff)) return FinalClaim<F>::rejected(__LINE__);
    }

    // =========================================================================
    // 步骤 8: 验证最终 PoW
    // =========================================================================
    {
        if (!final_pow.verify(verifier_state, pow_engine_lookup)) return FinalClaim<F>::rejected(__LINE__);
    }

    // =========================================================================
    // 步骤 9: 验证最终域内（本地一致性检查）
    //
    // 使用验证者持有的 final_vector 和域内求值器，检查
    // 证明者开启的域内值是否与 final_vector 一致。
    // 捕获证明者发送错误 final_vector 的情况。
    // =========================================================================
    {
        irs_commit::Evaluations<F> in_domain;
        std::vector<F> poly_rlc;
        if (is_first_round) {
            auto in_domain_src = initial_committer.verify(verifier_state, commitments_ptr);
            if (in_domain_src.points.size() != initial_committer.in_domain_samples &&
                !initial_committer.deduplicate_in_domain) return FinalClaim<F>::rejected(__LINE__);
            if (in_domain_src.matrix.size() != in_domain_src.points.size()
                * commitments_ptr.size() * initial_committer.num_cols()) return FinalClaim<F>::rejected(__LINE__);
            in_domain = in_domain_src.template lift<M>(*embedding());
            poly_rlc = vector_rlc_coeffs;
        } else {
            auto& prev_rc = round_configs.back();
            std::vector<const irs_commit::Commitment<F>*> cptrs{prev_round_commitment};
            in_domain = prev_rc.irs_committer.verify(verifier_state, cptrs);
            if (in_domain.points.size() != prev_rc.irs_committer.in_domain_samples &&
                !prev_rc.irs_committer.deduplicate_in_domain) return FinalClaim<F>::rejected(__LINE__);
            if (in_domain.matrix.size() != in_domain.points.size()
                * prev_rc.irs_committer.num_cols()) return FinalClaim<F>::rejected(__LINE__);
            poly_rlc = {F::one()};
        }

        // 检查: evaluator.evaluate(final_vector) == opened value（每个挑战点）
        auto weights_iter = in_domain.evaluators(final_vector.size());
        auto& last_fr = round_fr.back();
        auto eq_w = last_fr.coords.size() > 0 ? last_fr.eq_weights() : std::vector<F>{F::one()};
        auto tp = ::whir::algebra::tensor_product<F>(poly_rlc, eq_w);
        auto vals = in_domain.values(tp);

        for (std::size_t i = 0; i < weights_iter.size() && i < vals.size(); ++i) {
            ::whir::algebra::Identity<F> identity;
            F expected = weights_iter[i].evaluate(identity, final_vector);
            if (expected != vals[i]) return FinalClaim<F>::rejected(__LINE__);
        }
    }

    // =========================================================================
    // 步骤 10: 最终 sumcheck 验证
    // =========================================================================
    auto final_fr = final_sumcheck.verify(verifier_state, the_sum);
    if (final_fr.coords.size() != final_sumcheck.num_rounds) return FinalClaim<F>::rejected(__LINE__);
    round_fr.push_back(std::move(final_fr));

    // =========================================================================
    // 步骤 11: 拼接所有 sumcheck 坐标为 evaluation_point
    // =========================================================================
    std::vector<F> evaluation_point;
    for (const auto& mp : round_fr)
        evaluation_point.insert(evaluation_point.end(), mp.coords.begin(), mp.coords.end());

    // =========================================================================
    // 步骤 12: 从 sumcheck 不变量恢复 linear_form_rlc
    //
    // 核心不变量:
    //   final_poly(evaluation_point) * linear_form_rlc = the_sum
    //
    // 恢复:
    //   linear_form_rlc = the_sum / final_poly(final_vector)
    //   然后减去逐轮约束贡献:
    //     linear_form_rlc -= SUM_i weights_rlc[i] * weights[i].mle_evaluate(ep_slice)
    //
    // 结果等于初始约束 RLC 在 evaluation_point 处的求值，
    // 验证者通过 FinalClaim.verify(linear_forms) 检查
    // =========================================================================

    // 从最终 sumcheck 多项式构造 MLE 并在 final_vector 处求值
    ::whir::algebra::MultilinearExtension<F> poly_mle(
        std::vector<F>(round_fr.back().coords));
    F poly_eval = poly_mle.evaluate(::whir::algebra::Identity<F>{}, final_vector);
    F linear_form_rlc = the_sum;
    if (poly_eval != F::zero()) {
        linear_form_rlc = linear_form_rlc * poly_eval.inverse();
    }

    // 减去逐轮约束贡献（OOD + STIR）
    for (std::size_t r = 0; r < round_constraints.size(); ++r) {
        const auto& [weights_rlc, weights] = round_constraints[r];
        // 第 r 轮的变量数（r=0 时为初始，否则为前一轮）
        std::size_t num_vars = (r == 0)
            ? static_cast<std::size_t>(::whir::algebra::ntt::trailing_zeros(initial_committer.vector_size))
            : static_cast<std::size_t>(::whir::algebra::ntt::trailing_zeros(
                round_configs[r - 1].irs_committer.vector_size));

        // 取 evaluation_point 的最后 num_vars 个坐标
        std::size_t start = evaluation_point.size() >= num_vars
            ? evaluation_point.size() - num_vars : 0;
        std::span<const F> ep_slice{evaluation_point.data() + start, evaluation_point.size() - start};

        for (std::size_t i = 0; i < weights_rlc.size() && i < weights.size(); ++i)
            linear_form_rlc -= weights_rlc[i] * weights[i].mle_evaluate(ep_slice);
    }

    return FinalClaim<F>{
        std::move(evaluation_point),
        std::vector<F>(initial_forms_rlc.begin(), initial_forms_rlc.end()),
        linear_form_rlc,
    };
}

} // namespace whir::protocols::whir
