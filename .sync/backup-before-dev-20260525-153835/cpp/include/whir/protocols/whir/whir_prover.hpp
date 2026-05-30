#pragma once

// ============================================================================
// whir_prover.hpp — WHIR 证明者: Config<M>::prove() 实现
//
// 10 步证明流程。由 whir.hpp 在文件末尾包含，不要直接包含。
//
// 对应 Rust 文件: src/protocols/whir/prover.rs
// ============================================================================

#include "../geometric_challenge.hpp"
#include "../../algebra/linear_form.hpp"
#include "../../algebra/multilinear.hpp"
#include "../../algebra/sumcheck.hpp"
#include "../../algebra/utilities.hpp"
#include "../../hash/blake3_engine.hpp"
#include "../../hash/sha2_engine.hpp"
#include "../../profiling.hpp"
#include "../../utils.hpp"

#include <cassert>
#include <deque>
#include <memory>
#include <span>
#include <vector>

namespace whir::protocols::whir {

// ============================================================================
// Config<M>::prove() — 完整 WHIR 证明（10 步）
//
// prover_state  — Fiat-Shamir transcript
// vectors_span  — 原始向量（基域，每个长度为 initial_size）
// witnesses     — commit() 产生的 Witness 列表（RS 矩阵 + Merkle + OOD 求值）
// linear_forms  — 约束线性形式（unique_ptr 列表，每个长度为 initial_size）
// evaluations   — 声明的求值: eval[i * nvec + j] = linear_form[i](vector[j])
//
// 返回 FinalClaim<Target>:
//   evaluation_point — 所有 sumcheck 轮坐标的拼接
//   rlc_coefficients — 初始约束 RLC 系数
//   linear_form_rlc  — F::zero()（由验证者计算）
//
// 步骤:
//   1. 补全跨承诺 OOD 求值
//   2. 向量 RLC（几何挑战 → vector_rlc）
//   3. 约束 RLC（几何挑战 → constraint_rlc + oods_rlc）
//   4. 计算 "The Sum"（向量 RLC · 求值 RLC + OOD 约束）
//   5. 初始 sumcheck
//   6. 逐轮 STIR: IRS commit → PoW → 开启前一轮 → STIR 约束 → sumcheck
//   7. 发送最终向量（明文）
//   8. 最终 PoW
//   9. 开启最终 witness（域内验证）
//  10. 最终 sumcheck
// ============================================================================

template <typename M>
template <typename Transcript>
FinalClaim<typename M::Target> Config<M>::prove(
    Transcript& prover_state,
    std::span<const std::span<const Source>> vectors_span,
    std::span<const irs_commit::Witness<Source, Target>> witnesses,
    std::vector<std::unique_ptr<::whir::algebra::LinearForm<Target>>>    linear_forms,
    std::span<const Target> evaluations) const
{
    using F = Target;
    const std::size_t num_vectors = vectors_span.size();
    const std::size_t num_linear_forms = linear_forms.size();

    // ---- 输入校验 ----
    assert(num_vectors == witnesses.size() * initial_committer.num_vectors);
    assert(evaluations.size() == num_vectors * num_linear_forms);
    for (const auto& v : vectors_span) assert(v.size() == initial_size());
    for (const auto& lf : linear_forms) assert(lf->size() == initial_size());
    if (num_vectors == 0) return FinalClaim<F>{};

    ::whir::hash::Blake3 blake3_pow_engine;
    ::whir::hash::Sha2 sha2_pow_engine;
    auto pow_engine_lookup =
        [&blake3_pow_engine, &sha2_pow_engine](::whir::EngineId id)
            -> const ::whir::hash::HashEngine& {
        if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_pow_engine;
        return blake3_pow_engine;
    };

    // =========================================================================
    // 步骤 1: 补全跨承诺 OOD 求值
    //
    // 每个 witness 仅包含其管理向量的 OOD 求值。
    // STIR 折叠要求每个向量在每个 OOD 点均有求值。
    // 对不在当前 witness 中的向量，计算并通过 transcript 发送缺失的 OOD 求值。
    // =========================================================================
    std::vector<::whir::algebra::UnivariateEvaluation<F>> oods_evals; //OOD求值器列表 
    std::vector<F> oods_matrix; //OOD求值矩阵
    {
        ::whir::profile::ScopedTimer timer("prover", initial_size(), "prove_ood_completion");
        std::size_t vector_offset = 0;
        for (const auto& witness : witnesses) {
            //out_of_domain是域外求值结果Evaluation
            auto w_evals = witness.out_of_domain.evaluators(initial_size());
            std::size_t w_cols = witness.out_of_domain.num_columns();

            for (std::size_t ei = 0; ei < w_evals.size(); ++ei) {
                const auto& oods_eval = w_evals[ei];

                for (std::size_t j = 0; j < num_vectors; ++j) {
                    if (j >= vector_offset && j < w_cols + vector_offset) {
                        // 向量由当前 witness 管理，复用预计算值
                        oods_matrix.push_back(
                            witness.out_of_domain.matrix[ei * w_cols + (j - vector_offset)]);
                    } else {
                        // 向量不在当前 witness 中，通过嵌入求值并发送
                        F eval = oods_eval.evaluate(*embedding(), vectors_span[j]);
                        prover_state.prover_message(eval);
                        oods_matrix.push_back(eval);
                    }
                }
                oods_evals.push_back(oods_eval);
            }
            vector_offset += witness.num_vectors();
        }
    }

    // =========================================================================
    // 步骤 2: 向量 RLC（随机线性组合）
    //
    // geometric_challenge 从 transcript 生成几何级数:
    //   coeff[0]=1, coeff[i+1] = coeff[i] * alpha
    //
    // 组合向量: vector = SUM_i coeff[i] * lift(vectors[i])
    // 其中 lift 将基域元素映射到扩域
    // =========================================================================
    auto vector_rlc_coeffs = geometric_challenge<F>(prover_state, num_vectors);
    assert(vector_rlc_coeffs[0] == F::one());

    std::vector<F> vector;
    {
        ::whir::profile::ScopedTimer timer("prover", initial_size(), "vector_rlc");
        vector = ::whir::algebra::lift<M>(*embedding(), vectors_span[0]);
        for (std::size_t i = 1; i < num_vectors; ++i)
            ::whir::algebra::mixed_scalar_mul_add<M>(*embedding(), vector, vector_rlc_coeffs[i], vectors_span[i]);
    }

    // =========================================================================
    // 步骤 3: 约束 RLC
    //
    // 对 num_linear_forms 个约束 + oods_evals.size() 个 OOD 约束做 RLC。
    // 结果分为两段:
    //   initial_forms_rlc[0..num_linear_forms) — 初始约束系数
    //   oods_rlc[0..oods_evals.size())         — OOD 约束系数
    // =========================================================================
    auto constraint_rlc_coeffs = geometric_challenge<F>(prover_state,
        num_linear_forms + oods_evals.size());

    bool has_constraints = !constraint_rlc_coeffs.empty();
    std::span<const F> initial_forms_rlc(constraint_rlc_coeffs.data(), num_linear_forms);
    std::span<const F> oods_rlc(std::span{constraint_rlc_coeffs}.subspan(num_linear_forms));

    // 构建 covector = SUM_i constraint_rlc[i] * linear_form[i]
    // 用于内积 <vector, covector>
    std::vector<F> covector;
    if (num_linear_forms > 0) {
        covector.resize(initial_size(), F::zero());
        linear_forms[0]->accumulate(covector, F::one()); //covector是accumulator,F::one是weight
        for (std::size_t i = 1; i < num_linear_forms; ++i) 
            linear_forms[i]->accumulate(covector, constraint_rlc_coeffs[i]);
    } else if (has_constraints) {
        covector.resize(initial_size(), F::zero());
    }

    // =========================================================================
    // 步骤 4: 计算 "The Sum" — 初始 sumcheck 的目标值
    //
    // the_sum = SUM_i constraint_rlc[i] * (SUM_j vector_rlc[j] * eval[i][j])
    //         + SUM_i oods_rlc[i]       * (SUM_j vector_rlc[j] * ood_matrix[i][j])
    //
    // 直觉: 对求值矩阵（行=约束，列=向量）做双重 RLC，再加上 OOD 约束贡献
    // =========================================================================
    F the_sum = F::zero();

    // 初始约束: row_sum = SUM_j vector_rlc[j] * eval[i][j]
    for (std::size_t i = 0; i < num_linear_forms; ++i) {
        F row_sum = F::zero();
        for (std::size_t j = 0; j < num_vectors; ++j)
            row_sum += vector_rlc_coeffs[j] * evaluations[i * num_vectors + j];
        the_sum += constraint_rlc_coeffs[i] * row_sum;
    }

    // OOD 约束: 将 OOD 求值器累积到 covector，然后累加其和
    ::whir::algebra::UnivariateEvaluation<F>::accumulate_many(oods_evals, covector, oods_rlc);
    for (std::size_t i = 0; i < oods_rlc.size(); ++i) {
        F row_sum = F::zero();
        for (std::size_t j = 0; j < num_vectors; ++j)
            row_sum += vector_rlc_coeffs[j] * oods_matrix[i * num_vectors + j];
        the_sum += oods_rlc[i] * row_sum;
    }

    // =========================================================================
    // 步骤 5: 初始 sumcheck
    //
    // 有约束: 运行 sumcheck 验证 <vector, covector> = the_sum，
    //   每轮获得折叠坐标
    // 无约束: 验证者直接挤压随机坐标，
    //   运行 skip-PoW（transcript 一致性），手动折叠向量
    // =========================================================================
    std::vector<F> evaluation_point;
    bool is_first_round = true;

    if (has_constraints) {
        ::whir::profile::ScopedTimer timer("prover", initial_size(), "initial_sumcheck");
        auto fr = initial_sumcheck.prove(prover_state, vector, covector, the_sum);
        evaluation_point = std::move(fr.coords);
    } else {
        ::whir::profile::ScopedTimer timer("prover", initial_size(), "initial_fold_without_sumcheck");
        auto fr = prover_state.template verifier_message_vec<F>(initial_sumcheck.num_rounds);
        initial_skip_pow.prove(prover_state, pow_engine_looku  p);
        for (auto& f : fr) ::whir::algebra::fold<F>(vector, f);
        covector.assign(initial_sumcheck.final_size(), F::zero());
        evaluation_point = std::move(fr);
    }

    // =========================================================================
    // 步骤 6: 逐轮 STIR（Sumcheck + Tensor + Interleaved RS）
    //
    // 每轮:
    //   6a. IRS 承诺当前折叠向量
    //   6b. PoW（抗 grinding）
    //   6c. 开启前一轮 witness（域内挑战 + Merkle 路径）
    //       - 首轮: 开启多个初始 witness，提升到扩域
    //       - 后续: 开启单个前一轮 witness
    //   6d. 收集 STIR 约束（OOD + 域内）
    //       - 域内权重 = tensor_product(vector_rlc, eq_weights)
    //       - eq_weights 仅由前一轮折叠随机性推导
    //   6e. STIR sumcheck → 扩展 evaluation_point
    //
    // 折叠效果: 每轮向量长度减半（少一个变量）
    // =========================================================================
    const irs_commit::Witness<F, F>* prev_round_witness = nullptr;

    // 用 deque 存储所有轮 witness 以保证指针稳定性
    // （Rust 通过 RoundWitness 枚举持有所有权；C++ 用 deque 保证稳定指针）
    std::deque<irs_commit::Witness<F, F>> stored_round_witnesses;

    // 前一轮 sumcheck 折叠随机性（用于步骤 6d 的 eq_weights）
    // 从初始 sumcheck 输出初始化
    std::vector<F> last_fr_coords = evaluation_point;

    for (std::size_t round_idx = 0; round_idx < round_configs.size(); ++round_idx) {
        const auto& rc = round_configs[round_idx];

        // --- 6a. IRS 承诺当前折叠向量 ---
        std::span<const F> vec_single{vector};
        std::vector<std::span<const F>> single_span{vec_single};
        irs_commit::Witness<F, F> new_witness;
        {
            ::whir::profile::ScopedTimer timer("prover", rc.irs_committer.size(), "round_commit");
            new_witness = rc.irs_committer.commit(prover_state, single_span);
        }

        // --- 6b. PoW ---
        {
            ::whir::profile::ScopedTimer timer("prover", rc.sumcheck.initial_size, "round_pow");
            rc.pow.prove(prover_state, pow_engine_lookup);
        }

        // --- 6c. 开启前一轮 witness ---
        irs_commit::Evaluations<F> in_domain;
        if (is_first_round) {
            // 首轮: 开启 initial_committer 的多个 witness，然后提升
            std::vector<const irs_commit::Witness<Source, Target>*> wptrs;
            wptrs.reserve(witnesses.size());
            for (const auto& w : witnesses) wptrs.push_back(&w);
            ::whir::profile::ScopedTimer timer("prover", initial_committer.codeword_length, "opening");
            auto in_domain_src = initial_committer.open(prover_state, wptrs);
            in_domain = in_domain_src.template lift<M>(*embedding());
            is_first_round = false;
        } else {
            // 后续: 开启前一轮的单个 witness
            auto& prev_rc = round_configs[round_idx - 1];
            std::vector<const irs_commit::Witness<F, F>*> wptrs{prev_round_witness};
            ::whir::profile::ScopedTimer timer("prover", prev_rc.irs_committer.codeword_length, "opening");
            in_domain = prev_rc.irs_committer.open(prover_state, wptrs);
        }

        // --- 6d. 收集 STIR 约束 ---
        {
            ::whir::profile::ScopedTimer timer("prover", rc.sumcheck.initial_size, "round_stir_constraints");
            // 新 witness 的 OOD 求值器 + 开启操作的域内求值器
            std::vector<::whir::algebra::UnivariateEvaluation<F>> stir_challenges;
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_evaluators");
                stir_challenges = new_witness.out_of_domain.evaluators(rc.sumcheck.initial_size);
                auto in_domain_evals = in_domain.evaluators(rc.sumcheck.initial_size);
                stir_challenges.insert(stir_challenges.end(), in_domain_evals.begin(), in_domain_evals.end());
            }

            // OOD 值（权重 = [1]）+ 域内值（权重 = tensor_product）
            // eq_weights 仅使用前一轮折叠随机性（非累积）
            F one_val = F::one();
            std::vector<F> stir_evaluations;
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_ood_values");
                stir_evaluations = new_witness.out_of_domain.values(std::span<const F>{&one_val, 1});
            }

            std::vector<F> eq_w;
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_eq_weights");
                eq_w = last_fr_coords.empty()
                    ? std::vector<F>{F::one()}
                    : ::whir::algebra::MultilinearPoint<F>(last_fr_coords).eq_weights();
            }
            std::vector<F> tp;
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_tensor_product");
                tp = ::whir::algebra::tensor_product<F>(vector_rlc_coeffs, eq_w);
            }
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_in_domain_values");
                auto in_domain_vals = in_domain.values(tp);
                stir_evaluations.insert(stir_evaluations.end(), in_domain_vals.begin(), in_domain_vals.end());
            }

            // STIR RLC: 对所有 STIR 约束做随机线性组合
            std::vector<F> stir_rlc;
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_rlc");
                stir_rlc = geometric_challenge<F>(prover_state, stir_challenges.size());
            }
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_accumulate_many");
                ::whir::algebra::UnivariateEvaluation<F>::accumulate_many(stir_challenges, covector, stir_rlc);
            }
            {
                ::whir::profile::ScopedTimer sub_timer("prover", rc.sumcheck.initial_size, "round_stir_dot");
                the_sum += ::whir::algebra::dot<F>(stir_rlc, stir_evaluations);
            }
        }

        // --- 6e. STIR sumcheck ---
        {
            ::whir::profile::ScopedTimer timer("prover", rc.sumcheck.initial_size, "round_sumcheck_folding");
            auto fr = rc.sumcheck.prove(prover_state, vector, covector, the_sum);
            evaluation_point.insert(evaluation_point.end(), fr.coords.begin(), fr.coords.end());
            last_fr_coords = std::move(fr.coords);
        }

        // 更新下一轮状态: 单向量，RLC = [1]
        vector_rlc_coeffs = {F::one()};

        // 持久化 witness: 下一轮的 open（步骤 6c）和最终 open（步骤 9）需要
        stored_round_witnesses.push_back(std::move(new_witness));
        prev_round_witness = &stored_round_witnesses.back();
    }

    // =========================================================================
    // 步骤 7: 发送最终向量（明文系数）
    //
    // 所有轮结束后，vector 已折叠至 final_size。发送全部系数
    // 以便验证者检查最终 sumcheck 一致性。
    // =========================================================================
    assert(vector.size() == final_sumcheck.initial_size);
    for (const auto& coeff : vector)
        prover_state.prover_message(coeff);

    // =========================================================================
    // 步骤 8: 最终 PoW
    // =========================================================================
    {
        ::whir::profile::ScopedTimer timer("prover", final_sumcheck.initial_size, "final_pow");
        final_pow.prove(prover_state, pow_engine_lookup);
    }

    // =========================================================================
    // 步骤 9: 开启最终 witness（域内验证）
    //
    // 若 is_first_round（从未进入主循环）: 开启 initial_committer witness
    // 否则: 开启最后一轮的 witness
    // =========================================================================
    if (is_first_round) {
        std::vector<const irs_commit::Witness<Source, Target>*> wptrs;
        for (const auto& w : witnesses) wptrs.push_back(&w);
        ::whir::profile::ScopedTimer timer("prover", initial_committer.codeword_length, "final_opening");
        initial_committer.open(prover_state, wptrs);
    } else if (prev_round_witness) {
        auto& prev_rc = round_configs.back();
        std::vector<const irs_commit::Witness<F, F>*> wptrs{prev_round_witness};
        ::whir::profile::ScopedTimer timer("prover", prev_rc.irs_committer.codeword_length, "final_opening");
        prev_rc.irs_committer.open(prover_state, wptrs);
    }

    // =========================================================================
    // 步骤 10: 最终 sumcheck
    //
    // 在完全折叠的域上验证 <vector, covector> = the_sum
    // 将返回的坐标追加到 evaluation_point
    // =========================================================================
    {
        ::whir::profile::ScopedTimer timer("prover", final_sumcheck.initial_size, "final_sumcheck");
        auto final_fr = final_sumcheck.prove(prover_state, vector, covector, the_sum);
        evaluation_point.insert(evaluation_point.end(), final_fr.coords.begin(), final_fr.coords.end());
    }

    return FinalClaim<F>{
        std::move(evaluation_point),
        std::vector<F>(initial_forms_rlc.begin(), initial_forms_rlc.end()),
        F::zero(),
    };
}

} // namespace whir::protocols::whir
