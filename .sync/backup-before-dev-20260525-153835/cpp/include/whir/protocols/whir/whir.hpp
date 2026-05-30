#pragma once

// ============================================================================
// whir.hpp — WHIR 协议核心类型定义
//
// WHIR（Witness-Hiding Interleaved Reed-Solomon）是多项式 IOP 协议族：
//   1. 通过 IRS 编码 + Merkle 树承诺多个多项式
//   2. 逐轮 STIR 折叠缩减域大小
//   3. 最终轻量级 sumcheck 验证
//
// 数据流:
//   证明者: vectors → commit → prove(STIR fold → sumcheck) → FinalClaim
//   验证者: receive_commitment → verify(STIR fold → sumcheck) → FinalClaim.verify
//
// 对应 Rust 文件: src/protocols/whir/{mod.rs, config.rs}
// ============================================================================

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
#include <cstdint>
#include <utility>
#include <vector>

namespace whir::protocols::whir {

// 前向声明
template <typename F>
struct FinalClaim;

// 移动赋值 IRS 配置。构造 Config 时用于填充初始和逐轮 committer，
// 避免拷贝 Merkle 层向量。
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

// ============================================================================
// RoundConfig<F> — 单轮 WHIR 配置
//
// 每轮依次执行三个子协议:
//   IRS commit → PoW → 开启前一轮 witness → STIR 约束收集 → Sumcheck
// ============================================================================

template <typename F>
struct RoundConfig {
    // 当前轮折叠向量的 IRS 承诺器（RS 编码 + Merkle 树）
    // Identity<F> 表示基域和扩域相同（域内/域外共享同一域）
    irs_commit::Config<::whir::algebra::Identity<F>> irs_committer;

    // 验证折叠后声明的 sumcheck 配置
    sumcheck::Config<F> sumcheck;

    // 抗 grinding 攻击的工作量证明
    pow::PowConfig pow;
};

// ============================================================================
// Config<M> — WHIR 协议全局配置
//
// 模板参数 M: 嵌入映射 F → G（基域 → 扩域）
//
// 分层结构:
//   initial_committer / initial_sumcheck — 处理原始输入向量
//   round_configs[]                     — 逐轮 IRS + Sumcheck + PoW
//   final_sumcheck / final_pow          — 折叠至最简域后执行
// ============================================================================

template <typename M>
struct Config {
    using Source = typename M::Source;   // 基域 F
    using Target = typename M::Target;   // 扩域 G

    // ---- 初始阶段 ----
    irs_commit::Config<M> initial_committer;
    sumcheck::Config<Target> initial_sumcheck;
    pow::PowConfig initial_skip_pow;           // 无约束时的占位 PoW

    // ---- 逐轮阶段 ----
    std::vector<RoundConfig<Target>> round_configs;

    // ---- 最终阶段 ----
    sumcheck::Config<Target> final_sumcheck;
    pow::PowConfig final_pow;

    // -------------------------------------------------------------------------
    // 从协议参数构造完整 Config。
    //
    // size   — 初始多项式长度（必须是 2 的幂）
    // params — ProtocolParameters（安全等级、码率、折叠因子等）
    //
    // PoW 难度由目标安全级别与各子协议阶段 RBR 可靠性之间的差值推导。
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

        // PoW 配置工厂: 难度（比特）→ 阈值
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

        // 初始折叠 PoW: gap = security - min(proximity_gap, field_bits - log(list_size) - 1)
        double starting_folding_pow_bits = [&]() {
            double pg = c.initial_committer.rbr_soundness_fold_prox_gaps(field_size_bits);
            double ll = std::log2(c.initial_committer.list_size());
            return std::max(security - std::min(pg, field_size_bits - ll - 1.0), 0.0);
        }();
        // 跳过 PoW: 无约束声明时使用（仅保证 transcript 一致性）
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

        // 构建逐轮配置: 每轮将域减半（消耗 folding_factor 个变量）
        while (num_vars >= params.folding_factor) {
            std::size_t rff = (rd == 0) ? params.initial_folding_factor : params.folding_factor;
            std::size_t nli = log_inv_rate + (rff - 1);
            double rr = std::pow(0.5, static_cast<double>(nli));

            RoundConfig<Target> rc;
            assign_irs_config(rc.irs_committer,
                irs_commit::Config<::whir::algebra::Identity<Target>>::from_params(
                    protocol_security, params.unique_decoding, params.hash_id,
                    1, 1 << num_vars, 1 << params.folding_factor, rr, field_size_bits));

            // 组合绑定误差: min(query_entropy, coll_bound_error)
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

        // 最终开启 PoW: 覆盖 security - rbr_e 差距
        double fpb2 = std::max(security - rbr_e, 0.0);
        // 最终折叠 PoW: 覆盖 security - field_size_bits + 1 差距
        double ffpb = std::max(security - field_size_bits + 1.0, 0.0);

        // 最终 sumcheck 折叠剩余 num_vars 个变量至完成
        c.final_sumcheck.initial_size = 1 << num_vars;
        c.final_sumcheck.num_rounds = num_vars;
        c.final_sumcheck.round_pow = pow_cfg(ffpb);
        c.final_pow = pow_cfg(fpb2);

        return c;
    }

    // 检查所有子配置是否使用唯一解码（无列表解码）
    bool unique_decoding() const {
        if (!initial_committer.unique_decoding()) return false;
        for (const auto& r : round_configs)
            if (!r.irs_committer.unique_decoding()) return false;
        return true;
    }

    const M* embedding() const { return initial_committer.embedding(); }

    std::size_t initial_size() const { return initial_committer.vector_size; }
    std::size_t final_size() const { return final_sumcheck.final_size(); }
    std::size_t n_rounds() const { return round_configs.size(); }

    // -------------------------------------------------------------------------
    // 安全性分析（简化版，与 Rust security_level() 对齐）
    //
    // 计算所有可靠性瓶颈项的最小值:
    //   - 域大小约束（向量数 / 线性形式数）
    //   - OOD 采样误差（仅列表解码）
    //   - 逐轮: 组合绑定误差 + PoW、折叠邻近性 + PoW
    //   - 最终: 查询熵 + PoW、最终 sumcheck 折叠 + PoW
    // -------------------------------------------------------------------------
    double security_level(std::size_t num_vectors, std::size_t num_linear_forms) const {
        double field_size_bits = Target::field_size_bits;
        double sec = 1e308; // INFINITY
        if (num_vectors > 1)
            sec = std::min(sec, field_size_bits - std::log2(static_cast<double>(num_vectors - 1)));
        if (num_linear_forms > 1)
            sec = std::min(sec, field_size_bits - std::log2(static_cast<double>(num_linear_forms - 1)));

        if (!initial_committer.unique_decoding())
            sec = std::min(sec, initial_committer.rbr_ood_sample(field_size_bits));

        // 初始折叠误差
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
    // IRS 承诺（证明者端）。委托给 initial_committer.commit()。
    //
    // prover_state — Fiat-Shamir transcript
    // vectors      — 输入向量 (num_vectors x initial_size)
    //
    // 返回: Witness，包含 RS 编码矩阵、Merkle 树、OOD 求值
    // -------------------------------------------------------------------------
    template <typename Transcript>
    irs_commit::Witness<Source, Target> commit(
        Transcript& prover_state,
        std::span<const std::span<const Source>> vectors) const
    {
        return initial_committer.commit(prover_state, vectors);
    }

    // -------------------------------------------------------------------------
    // 接收承诺（验证者端）。委托给 initial_committer.receive_commitment()。
    //
    // verifier_state — 包含已加载证明的 transcript
    //
    // 返回: Commitment，包含 Merkle 根 + OOD 求值点和值
    // -------------------------------------------------------------------------
    template <typename Transcript>
    irs_commit::Commitment<Target> receive_commitment(
        Transcript& verifier_state) const
    {
        return initial_committer.receive_commitment(verifier_state);
    }

    // -------------------------------------------------------------------------
    // 完整 WHIR 证明（证明者端）。实现在 whir_prover.hpp。
    //
    // prover_state  — Fiat-Shamir transcript
    // vectors       — 原始向量（基域）
    // witnesses     — commit() 产生的 Witness 列表
    // linear_forms  — 约束线性形式（unique_ptr 列表）
    // evaluations   — 声明的求值: eval[i*nvec+j] = linear_form[i](vector[j])
    //
    // 返回: FinalClaim（evaluation_point + RLC 系数）
    // -------------------------------------------------------------------------
    template <typename Transcript>
    FinalClaim<Target> prove(
        Transcript& prover_state,
        std::span<const std::span<const Source>> vectors,
        std::span<const irs_commit::Witness<Source, Target>> witnesses,
        std::vector<std::unique_ptr<::whir::algebra::LinearForm<Target>>> linear_forms,
        std::span<const Target> evaluations) const;

    // -------------------------------------------------------------------------
    // 完整 WHIR 验证（验证者端）。实现在 whir_verifier.hpp。
    //
    // verifier_state — 包含已加载证明的 transcript
    // commitments    — receive_commitment() 产生的 Commitment 列表
    // evaluations    — 声明的求值
    //
    // 返回: FinalClaim（evaluation_point + RLC 系数 + linear_form_rlc）
    // -------------------------------------------------------------------------
    template <typename Transcript>
    FinalClaim<Target> verify(
        Transcript& verifier_state,
        std::span<const irs_commit::Commitment<Target>*> commitments,
        std::span<const Target> evaluations) const;
};

// ============================================================================
// 类型别名，与 Rust API 保持一致
// ============================================================================

template <typename F, typename M>
using Witness = irs_commit::Witness<typename M::Source, F>;

template <typename F>
using Commitment = irs_commit::Commitment<F>;

// ============================================================================
// FinalClaim<F> — WHIR 证明/验证的最终输出
//
// 字段:
//   evaluation_point — 所有 sumcheck 轮坐标的拼接
//   rlc_coefficients — 初始约束的随机线性组合系数
//   linear_form_rlc  — 在 evaluation_point 处的声明 RLC 值
//
// 验证者可本地检查:
//   SUM_i rlc_coefficients[i] * linear_forms[i].mle_evaluate(evaluation_point)
//     == linear_form_rlc
// ============================================================================

template <typename F>
struct FinalClaim {
    // 验证者在协议执行过程中拒绝时设为 false
    bool valid = false;
    std::uint32_t reject_code = 0;

    std::vector<F> evaluation_point;
    std::vector<F> rlc_coefficients;
    F linear_form_rlc;

    FinalClaim() : linear_form_rlc(F::zero()) {}

    static FinalClaim rejected(std::uint32_t code) {
        FinalClaim claim;
        claim.reject_code = code;
        return claim;
    }

    FinalClaim(std::vector<F> ep, std::vector<F> rlc, F lf_rlc)
        : valid(true)
        , evaluation_point(std::move(ep))
        , rlc_coefficients(std::move(rlc))
        , linear_form_rlc(lf_rlc) {}

    // -------------------------------------------------------------------------
    // 最终声明的本地验证
    //
    // 重新计算 SUM_i rlc_coefficients[i] * linear_forms[i].mle_evaluate(evaluation_point)
    // 并检查是否等于 linear_form_rlc
    //
    // 返回: true 接受，false 拒绝
    // -------------------------------------------------------------------------
    bool verify(const std::vector<const ::whir::algebra::LinearForm<F>*>& linear_forms) const {
        if (!valid) return false;
        if (rlc_coefficients.size() != linear_forms.size()) return false;
        F rlc = F::zero();
        for (std::size_t i = 0; i < rlc_coefficients.size(); ++i) {
            if (linear_forms[i] == nullptr) return false;
            rlc += rlc_coefficients[i] * linear_forms[i]->mle_evaluate(evaluation_point);
        }
        return rlc == linear_form_rlc;
    }
};

} // namespace whir::protocols::whir

// 模板成员函数实现（需要完整类型，在文件末尾包含）
#include "whir_prover.hpp"
#include "whir_verifier.hpp"
