#pragma once

// =============================================================================
// whir.hpp — WHIR 协议核心类型定义。
// 对应 WHIR 中的 src/protocols/whir/mod.rs 和 src/protocols/whir/config.rs。
//
// WHIR (Witness-Hiding Interleaved Reed-Solomon) 是多项式 IOP 协议族:
//   1. 把多个多项式的承诺 (IRS commit) 组合成一个"大声明"
//   2. 通过逐轮折叠 (STIR) 把声明缩减到越来越小的域
//   3. 最终用一个轻量级 sumcheck 验证折叠后的剩余声明
//
// 核心类型:
//   RoundConfig<F>  — 单轮 WHIR 配置 (IRS 承诺器 + Sumcheck + PoW)
//   Config<M>       — 全局配置, 包含初始/最终/逐轮的协议参数
//   FinalClaim<F>   — WHIR 验证的最终声明 (求值点 + RLC 系数)
//   Witness<F,M>    — 类型别名, 指向 irs_commit::Witness
//   Commitment<F>   — 类型别名, 指向 irs_commit::Commitment
//
// 数据流 (简化):
//   Prover:
//     vectors → commit(Merkle树) → prove(逐轮 STIR fold → sumcheck)
//     → open(域内挑战) → FinalClaim
//
//   Verifier:
//     receive_commitment → verify(逐轮 STIR fold → sumcheck验证)
//     → FinalClaim.verify(linear_forms)
//
// 安全模型:
//   - 唯一解码模式 (unique_decoding=true): 每个 IRS 使用唯一解码参数
//   - 列表解码模式: 允许更大的码率范围, 借助 Johnson 边界
//   - PoW (Proof of Work) 用于抵抗 Grinding 攻击
// =============================================================================

#include "../../algebra/embedding.hpp"
#include "../../algebra/linear_form.hpp"
#include "../../algebra/multilinear_point.hpp"
#include "../../bits.hpp"
#include "../../parameters.hpp"
#include "../irs_commit.hpp"
#include "../proof_of_work.hpp"
#include "../sumcheck_protocol.hpp"

#include <cassert>
#include <cmath>
#include <utility>
#include <vector>

namespace whir::protocols::whir {

// 前向声明
template <typename F>
struct FinalClaim;

template <typename M>
void assign_irs_config(
    irs_commit::Config<M>& dst,
    irs_commit::Config<M>&& src)
{
    dst.embedding_val = std::move(src.embedding_val);
    dst.num_vectors = src.num_vectors;
    dst.vector_size = src.vector_size;
    dst.codeword_length = src.codeword_length;
    dst.interleaving_depth = src.interleaving_depth;
    dst.matrix_commit_mt.num_leaves = src.matrix_commit_mt.num_leaves;
    dst.matrix_commit_mt.layers = std::move(src.matrix_commit_mt.layers);
    dst.matrix_commit_num_cols = src.matrix_commit_num_cols;
    dst.johnson_slack = src.johnson_slack;
    dst.in_domain_samples = src.in_domain_samples;
    dst.out_domain_samples = src.out_domain_samples;
    dst.deduplicate_in_domain = src.deduplicate_in_domain;
}

// =============================================================================
// RoundConfig<F> — 单轮 WHIR 配置。
//
// 每一轮 WHIR 包含三个子协议:
//   irs_committer — IRS 承诺配置 (对当前折叠向量的 RS 编码 + Merkle 树)
//   sumcheck      — Sumcheck 配置 (验证折叠后的声明)
//   pow           — Proof of Work 配置 (抵抗 Grinding 攻击)
//
// 每轮的数据流:
//   承诺新向量 → PoW → 打开前轮见证 → STIR 约束收集 → Sumcheck
// =============================================================================

template <typename F>
struct RoundConfig {
    // IRS 承诺器: 对当前轮的向量做 RS 编码 + Merkle 树承诺
    // Identity<F> 表示基域和扩展域相同 (域内/域外用同一域)
    irs_commit::Config<::whir::algebra::Identity<F>> irs_committer;

    // Sumcheck 配置: 验证折叠后声明的正确性
    sumcheck::Config<F> sumcheck;

    // PoW 配置: 反 Grinding, 确保 prover 不能通过反复尝试找到有利的挑战
    pow::PowConfig pow;
};

// =============================================================================
// Config<M> — WHIR 协议全局配置。
//
// 模板参数 M: 嵌入映射 F → G (基域 → 扩展域)。
//
// 配置分层:
//   initial_committer  — 初始 IRS 承诺 (对原始输入向量)
//   initial_sumcheck   — 初始 Sumcheck (对原始声明)
//   round_configs      — 逐轮配置列表 (每轮包括 IRS + Sumcheck + PoW)
//   final_sumcheck     — 最终 Sumcheck (折叠到最小域后的验证)
//   final_pow          — 最终 PoW
//
// 关键方法:
//   from_params(size, params)     — 从 ProtocolParameters 构造完整配置
//   commit(prover_state, vectors) — 委托给 initial_committer.commit()
//   receive_commitment(vs)        — 委托给 initial_committer.receive_commitment()
//   prove(prover_state, ...)      — 完整 WHIR 证明 (定义在 whir_prover.hpp)
//   verify(verifier_state, ...)   — 完整 WHIR 验证 (定义在 whir_verifier.hpp)
// =============================================================================

template <typename M>
struct Config {
    using Source = typename M::Source;   // 基域类型 (F)
    using Target = typename M::Target;   // 扩展域类型 (G)

    // ---- 初始阶段 ----
    irs_commit::Config<M> initial_committer;   // 初始 IRS 承诺配置
    sumcheck::Config<Target> initial_sumcheck; // 初始 Sumcheck 配置
    pow::PowConfig initial_skip_pow;           // 无约束时跳过的占位 PoW

    // ---- 逐轮阶段 ----
    std::vector<RoundConfig<Target>> round_configs; // 每轮的配置

    // ---- 最终阶段 ----
    sumcheck::Config<Target> final_sumcheck;  // 最终 Sumcheck
    pow::PowConfig final_pow;                 // 最终 PoW

    // -------------------------------------------------------------------------
    // from_params(size, params) — 从协议参数构造完整配置。
    //
    // 输入:
    //   size   — 初始多项式长度 (变量数)
    //   params — ProtocolParameters, 包含安全目标、码率、folding factor 等
    //
    // 输出: Config 实例 (具体数值计算由调用方完成)
    //
    // 对应 Rust: Config::new(size, params)
    // -------------------------------------------------------------------------
    static Config from_params(std::size_t size, const ::whir::ProtocolParameters& params)
    {
        Config c;

        assert((size & (size - 1)) == 0 && "size must be a power of two");

        double security = static_cast<double>(params.security_level);
        double protocol_security = static_cast<double>(
            params.security_level - params.pow_bits);
        double field_size_bits = Target::field_size_bits;

        std::size_t log_inv_rate = params.starting_log_inv_rate;
        std::size_t num_vars = 0;
        { std::size_t sz = size; while (sz > 1) { sz >>= 1; ++num_vars; } }

        auto pow_cfg = [&](double diff) -> pow::PowConfig {
            pow::PowConfig p;
            p.hash_id = params.hash_id;
            p.threshold_val = (diff <= 0.0) ? UINT64_MAX
                : static_cast<uint64_t>(std::ceil(std::exp2(64.0 - diff)));
            return p;
        };

        double initial_rate = std::pow(0.5, static_cast<double>(params.starting_log_inv_rate));
        assign_irs_config(c.initial_committer, irs_commit::Config<M>::from_params(
            protocol_security, params.unique_decoding, params.hash_id,
            params.batch_size, size, 1 << params.initial_folding_factor,
            initial_rate, field_size_bits));

        double starting_folding_pow_bits = [&]() {
            double pg = c.initial_committer.rbr_soundness_fold_prox_gaps(field_size_bits);
            double ll = std::log2(c.initial_committer.list_size());
            return std::max(security - std::min(pg, field_size_bits - ll - 1.0), 0.0);
        }();
        double skip_pow_bits = [&]() {
            double pg = c.initial_committer.rbr_soundness_fold_prox_gaps(field_size_bits)
                + std::log2(static_cast<double>(params.initial_folding_factor));
            return std::max(security - pg, 0.0);
        }();

        c.initial_sumcheck.initial_size = size;
        c.initial_sumcheck.num_rounds = params.initial_folding_factor;
        c.initial_sumcheck.round_pow = pow_cfg(starting_folding_pow_bits);
        c.initial_skip_pow = pow_cfg(skip_pow_bits);

        std::size_t rd = 0;
        std::size_t ids = c.initial_committer.in_domain_samples;
        double qe = c.initial_committer.rbr_queries();
        num_vars -= params.initial_folding_factor;

        while (num_vars >= params.folding_factor) {
            std::size_t rff = (rd == 0) ? params.initial_folding_factor : params.folding_factor;
            std::size_t nli = log_inv_rate + (rff - 1);
            double rr = std::pow(0.5, static_cast<double>(nli));

            RoundConfig<Target> rc;
            assign_irs_config(rc.irs_committer,
                irs_commit::Config<::whir::algebra::Identity<Target>>::from_params(
                    protocol_security, params.unique_decoding, params.hash_id,
                    1, 1 << num_vars, 1 << params.folding_factor, rr, field_size_bits));

            double cbe = [&]() {
                double ll = std::log2(rc.irs_committer.list_size());
                std::size_t cnt = rc.irs_committer.out_domain_samples + ids;
                return field_size_bits - (std::log2(static_cast<double>(cnt)) + ll + 1.0);
            }();
            double pb = std::max(security - std::min(qe, cbe), 0.0);
            double fpb = [&]() {
                double pg = rc.irs_committer.rbr_soundness_fold_prox_gaps(field_size_bits);
                double ll = std::log2(rc.irs_committer.list_size());
                return std::max(security - std::min(pg, field_size_bits - ll - 1.0), 0.0);
            }();

            rc.sumcheck.initial_size = 1 << num_vars;
            rc.sumcheck.num_rounds = params.folding_factor;
            rc.sumcheck.round_pow = pow_cfg(fpb);
            rc.pow = pow_cfg(pb);

            ++rd; num_vars -= params.folding_factor;
            log_inv_rate = nli;
            ids = rc.irs_committer.in_domain_samples;
            qe = rc.irs_committer.rbr_queries();
            c.round_configs.push_back(std::move(rc));
        }

        double rbr_e = c.round_configs.empty()
            ? c.initial_committer.rbr_queries()
            : c.round_configs.back().irs_committer.rbr_queries();

        //fpb2:最终打开PoW位(补齐security-rbr_e的缺口)
        double fpb2 = std::max(security - rbr_e, 0.0);
        //ffpb:最终折叠PoW位(补齐security-field_size+1的缺口)
        double ffpb = std::max(security - field_size_bits + 1.0, 0.0);

        //对最终sumcheck对剩余的num_vars个变量做完整折叠
        c.final_sumcheck.initial_size = 1 << num_vars;
        c.final_sumcheck.num_rounds = num_vars;
        c.final_sumcheck.round_pow = pow_cfg(ffpb);
        c.final_pow = pow_cfg(fpb2);

        return c;
    }

    // -------------------------------------------------------------------------
    // unique_decoding() — 检查所有子配置是否均为唯一解码模式。
    //
    // 输出: true 当且仅当 initial_committer 和所有 round 的 irs_committer
    //       都使用唯一解码 (无域外采样, 无 Johnson 松弛)
    // -------------------------------------------------------------------------
    bool unique_decoding() const {
        if (!initial_committer.unique_decoding()) return false;
        for (const auto& r : round_configs)
            if (!r.irs_committer.unique_decoding()) return false;
        return true;
    }

    const M* embedding() const { return initial_committer.embedding(); }

    // 初始向量大小 (变量数 = log2(initial_size))
    std::size_t initial_size() const { return initial_committer.vector_size; }

    // 最终折叠后的大小
    std::size_t final_size() const { return final_sumcheck.final_size(); }

    // 折叠轮数 = |round_configs|
    std::size_t n_rounds() const { return round_configs.size(); }

    // 安全分析 (简化版, 与 Rust security_level() 对齐)
    double security_level(std::size_t num_vectors, std::size_t num_linear_forms) const {
        double field_size_bits = Target::field_size_bits;
        double sec = 1e308; // INFINITY
        if (num_vectors > 1)
            sec = std::min(sec, field_size_bits - std::log2(static_cast<double>(num_vectors - 1)));
        if (num_linear_forms > 1)
            sec = std::min(sec, field_size_bits - std::log2(static_cast<double>(num_linear_forms - 1)));

        if (!initial_committer.unique_decoding())
            sec = std::min(sec, initial_committer.rbr_ood_sample(field_size_bits));

        // Initial fold error
        double prox = initial_committer.rbr_soundness_fold_prox_gaps(field_size_bits);
        double logL = std::log2(initial_committer.list_size());
        double init_fold = std::min(prox, field_size_bits - logL - 1.0)
            + static_cast<double>(initial_sumcheck.round_pow.difficulty());
        sec = std::min(sec, init_fold);

        double qe = initial_committer.rbr_queries();
        std::size_t ids = initial_committer.in_domain_samples;
        for (auto& r : round_configs) {
            if (!r.irs_committer.unique_decoding())
                sec = std::min(sec, r.irs_committer.rbr_ood_sample(field_size_bits));

            logL = std::log2(r.irs_committer.list_size());
            double cbe = field_size_bits
                - (std::log2(static_cast<double>(r.irs_committer.out_domain_samples + ids)) + logL + 1.0);
            sec = std::min(sec, std::min(qe, cbe) + static_cast<double>(r.pow.difficulty()));

            prox = r.irs_committer.rbr_soundness_fold_prox_gaps(field_size_bits);
            double fold_err = std::min(prox, field_size_bits - logL - 1.0)
                + static_cast<double>(r.sumcheck.round_pow.difficulty());
            sec = std::min(sec, fold_err);

            ids = r.irs_committer.in_domain_samples;
            qe = r.irs_committer.rbr_queries();
        }
        sec = std::min(sec, qe + static_cast<double>(final_pow.difficulty()));

        if (final_sumcheck.num_rounds > 0)
            sec = std::min(sec, field_size_bits - 1.0
                + static_cast<double>(final_sumcheck.round_pow.difficulty()));

        return std::isfinite(sec) ? sec : 0.0;
    }

    // -------------------------------------------------------------------------
    // commit(prover_state, vectors) — IRS 承诺 (prover 侧)。
    //
    // 输入:
    //   prover_state — ProverState (Fiat-Shamir transcript)
    //   vectors      — 原始向量列表 (num_vectors 个, 每个长度 = initial_size)
    //
    // 输出: irs_commit::Witness<Source, Target>
    //       - matrix: RS 编码矩阵 (codeword_length × num_cols)
    //       - matrix_witness: Merkle 树见证 (完整节点)
    //       - out_of_domain: 域外采样 + 求值
    //
    // 此函数直接委托给 initial_committer.commit()
    // -------------------------------------------------------------------------
    template <typename Transcript>
    irs_commit::Witness<Source, Target> commit(
        Transcript& prover_state,
        std::span<const std::span<const Source>> vectors) const
    {
        return initial_committer.commit(prover_state, vectors);
    }

    // -------------------------------------------------------------------------
    // receive_commitment(verifier_state) — 接收承诺 (verifier 侧)。
    //
    // 输入: verifier_state — VerifierState (已加载 proof 的 transcript)
    //
    // 输出: irs_commit::Commitment<Target>
    //       - matrix_commitment: Merkle 树根哈希
    //       - out_of_domain: 域外采样点 (确定性重放) + 域外求值
    //
    // 此函数直接委托给 initial_committer.receive_commitment()
    // -------------------------------------------------------------------------
    template <typename Transcript>
    irs_commit::Commitment<Target> receive_commitment(
        Transcript& verifier_state) const
    {
        return initial_committer.receive_commitment(verifier_state);
    }

    // -------------------------------------------------------------------------
    // prove(prover_state, vectors, witnesses, linear_forms, evaluations)
    //   — WHIR 完整证明 (prover 侧, 10 步)。
    //
    // 输入:
    //   prover_state  — ProverState (Fiat-Shamir transcript)
    //   vectors       — 原始向量 (基域)
    //   witnesses     — commit() 返回的 Witness 列表
    //   linear_forms  — 约束的线性形式 (每个约束是一个多线性多项式)
    //   evaluations   — 声明的求值结果: evaluations[i*nvec+j] = linear_form[i](vector[j])
    //
    // 输出: FinalClaim<Target> — 最终声明 (求值点 + RLC 系数)
    //
    // 实现: 见 whir_prover.hpp
    // -------------------------------------------------------------------------
    template <typename Transcript>
    FinalClaim<Target> prove(
        Transcript& prover_state,
        std::span<const std::span<const Source>> vectors,
        std::span<const irs_commit::Witness<Source, Target>> witnesses,
        std::vector<std::unique_ptr<::whir::algebra::LinearForm<Target>>> linear_forms,
        std::span<const Target> evaluations) const;

    // -------------------------------------------------------------------------
    // verify(verifier_state, commitments, evaluations)
    //   — WHIR 完整验证 (verifier 侧, 12 步)。
    //
    // 输入:
    //   verifier_state — VerifierState (含 proof 的 transcript)
    //   commitments    — receive_commitment() 返回的 Commitment 列表
    //   evaluations    — 声明的求值结果
    //
    // 输出: FinalClaim<Target> — 最终声明 (含 linear_form_rlc 计算结果)
    //
    // 实现: 见 whir_verifier.hpp
    // -------------------------------------------------------------------------
    template <typename Transcript>
    FinalClaim<Target> verify(
        Transcript& verifier_state,
        std::span<const irs_commit::Commitment<Target>*> commitments,
        std::span<const Target> evaluations) const;
};

// =============================================================================
// Witness / Commitment 类型别名 (对应 Rust)
// =============================================================================

template <typename F, typename M>
using Witness = irs_commit::Witness<typename M::Source, F>;

template <typename F>
using Commitment = irs_commit::Commitment<F>;

// =============================================================================
// FinalClaim<F> — WHIR 验证的最终声明。
//
// 证明结束后, prover 输出一个 FinalClaim, 其中:
//   evaluation_point  — 多线性扩张的求值点 (由所有 sumcheck 轮的坐标拼接而成)
//   rlc_coefficients   — 初始约束的随机线性组合系数
//   linear_form_rlc    — 约束 RLC 在 evaluation_point 处的声明值
//
// verifier 可以调用 FinalClaim::verify(linear_forms) 做本地检查:
//   用实际的线性形式重新计算 RLC 在 evaluation_point 处的值,
//   与声明的 linear_form_rlc 比对。若一致则接受, 否则拒绝。
//
// 输入:
//   linear_forms — 实际的线性形式列表 (verifier 本地持有)
//
// 输出: true 当且仅当 Σ rlc_coeffs[i] * linear_form[i](evaluation_point) == linear_form_rlc
// =============================================================================

template <typename F>
struct FinalClaim {
    // 多线性扩张求值点 (所有 sumcheck 轮坐标拼接)
    std::vector<F> evaluation_point;

    // 约束的随机线性组合系数 (prover 和 verifier 通过 transcript 确定性地挤出)
    std::vector<F> rlc_coefficients;

    // 声明的 RLC 在 evaluation_point 处的值
    F linear_form_rlc;

    FinalClaim() : linear_form_rlc(F::zero()) {}

    FinalClaim(std::vector<F> ep, std::vector<F> rlc, F lf_rlc)
        : evaluation_point(std::move(ep))
        , rlc_coefficients(std::move(rlc))
        , linear_form_rlc(lf_rlc) {}

    // -------------------------------------------------------------------------
    // verify(linear_forms) — 本地验证 FinalClaim。
    //
    // 输入: linear_forms — verifier 持有的实际线性形式 (const* 列表)
    //
    // 过程:
    //   对每个约束 i:
    //     rlc += rlc_coefficients[i] * linear_forms[i].mle_evaluate(evaluation_point)
    //   比对 rlc 与声明的 linear_form_rlc
    //
    // 输出: true 表示接受声明, false 表示拒绝
    // -------------------------------------------------------------------------
    bool verify(const std::vector<const ::whir::algebra::LinearForm<F>*>& linear_forms) const {
        assert(rlc_coefficients.size() == linear_forms.size());
        F rlc = F::zero();
        for (std::size_t i = 0; i < rlc_coefficients.size(); ++i) {
            rlc += rlc_coefficients[i] * linear_forms[i]->mle_evaluate(evaluation_point);
        }
        return rlc == linear_form_rlc;
    }
};

} // namespace whir::protocols::whir

// 模板成员函数实现 (需要完整类型, 放在最后 include)
#include "whir_prover.hpp"
#include "whir_verifier.hpp"
