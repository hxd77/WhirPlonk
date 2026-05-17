#pragma once

// =============================================================================
// whir_zk.hpp — Zero-Knowledge WHIR 协议核心类型。
// 对应 WHIR 中的 src/protocols/whir_zk/mod.rs。
//
// ZK WHIR 是 WHIR 的零知识变体: 证明者在不泄露多项式信息的情况下
// 证明对多项式的求值声明。核心思路:
//   1. 引入随机盲化多项式 (BlindingPolynomials) 掩盖原始多项式
//   2. 承诺 f_hat = f + mask (mask 是周期性的盲化多项式)
//   3. 同时承诺盲化多项式本身 (blinding commitment)
//   4. 证明者和验证者对 f_hat 和 blinding 各运行一轮 WHIR
//   5. 通过挑战值的约束关系确保盲化正确
//
// 核心类型:
//   BlindingSizePolicy — 盲化多项式大小的策略参数
//   ZkConfig<F>       — ZK WHIR 协议配置
//   ZkCommitment<F>   — ZK 承诺 (f_hat 承诺列表 + blinding 承诺)
//   ZkWitness<F>      — ZK 见证 (f_hat 向量 + blinding 多项式)
//
// 关键方法:
//   ZkConfig::commit(prover_state, polynomials, rng)
//     — 采样盲化多项式, 构造 f_hat = f + mask, 双重承诺
//   ZkConfig::prove(prover_state, vectors, witness, linear_forms, evaluations, rng)
//     — 11 步 ZK WHIR 证明
//   ZkConfig::verify(verifier_state, weights, evaluations, commitment)
//     — 9 步 ZK WHIR 验证
// =============================================================================

#include "../whir/whir.hpp"
#include "whir_zk_utils.hpp"
#include "../../algebra/embedding.hpp"
#include "../../algebra/ntt/utils.hpp"
#include "../../algebra/utilities.hpp"
#include "../../parameters.hpp"

#include <cassert>
#include <cmath>
#include <cstddef>
#include <vector>

namespace whir::protocols::whir_zk {

using ::whir::algebra::ntt::trailing_zeros;

// =============================================================================
// BlindingSizePolicy — 盲化多项式的大小策略。
//
// 控制盲化多项式的规模, 从而决定零知识的安全性和性能。
// 参数含义:
//   q_delta_1, q_delta_2 — 域内查询数的下界 (两个安全级别)
//   t1, t2              — 域内查询数 (通常 = q_delta_1/2)
//   sumcheck_round_degree — sumcheck 每轮的次数 (默认 3)
//
// 从 ProtocolParameters 自动推导:
//   from_whir_params(params) → BlindingSizePolicy
// 内部使用 num_in_domain_queries() 根据安全级别和码率计算所需查询数。
// =============================================================================

struct BlindingSizePolicy {
    std::size_t q_delta_1 = 0;   // 域内查询数 (主安全级别)
    std::size_t q_delta_2 = 0;   // 域内查询数 (宽松安全级别)
    std::size_t t1 = 0;          // 查询数副本 1
    std::size_t t2 = 0;          // 查询数副本 2
    std::size_t sumcheck_round_degree = 3; // sumcheck 次数

    // 从协议参数构造策略。
    // 输入: params — ProtocolParameters (安全级别, pow_bits, starting_log_inv_rate, unique_decoding)
    // 输出: BlindingSizePolicy (q1, q2, t1, t2, degree=3)
    static BlindingSizePolicy from_whir_params(const ::whir::ProtocolParameters& params) {
        double sec_level = static_cast<double>(params.security_level);
        double sec_level_main = static_cast<double>(params.security_level - params.pow_bits);
        double rate = std::pow(0.5, static_cast<double>(params.starting_log_inv_rate));
        auto q1 = static_cast<std::size_t>(std::ceil(
            ::whir::protocols::irs_commit::num_in_domain_queries(
                params.unique_decoding, sec_level_main, rate)));
        auto q2 = static_cast<std::size_t>(std::ceil(
            ::whir::protocols::irs_commit::num_in_domain_queries(
                params.unique_decoding, sec_level, rate)));
        return {q1, q2, q1, q2, 3};
    }
};

// 前向声明
template <typename F> struct ZkWitness;
template <typename F> struct ZkCommitment;

// =============================================================================
// ZkConfig<F> — ZK WHIR 协议配置。
//
// 包含两个内部 WHIR 配置:
//   blinded_commitment — 对 f_hat = f + mask 的 WHIR 承诺/证明
//   blinding_commitment — 对盲化多项式本身的 WHIR 承诺/证明
//
// 域参数:
//   omega_full() — 全域生成元 (阶 = codeword_length * interleaving_depth)
//   omega_sub()  — 子域生成元 (阶 = codeword_length)
//   zeta()       — coset 偏移 = omega_full^codeword_length
//
// 关键方法:
//   from_params(size, params, num_polynomials) — 构造配置
//   num_witness_variables() — 见证变量数 = log2(blinded_commitment.initial_size)
//   num_blinding_variables() — 盲化变量数 = log2(blinding_commitment.initial_size) - 1
//   all_gammas(query_points) — 对每个域内挑战点展开其 coset (共 id 个 gamma)
// =============================================================================

template <typename F>
struct ZkConfig {
    using Embedding = ::whir::algebra::Identity<F>;
    using WhirConfig = ::whir::protocols::whir::Config<Embedding>;

    WhirConfig blinded_commitment;   // f_hat 的 WHIR 配置
    WhirConfig blinding_commitment;  // 盲化多项式的 WHIR 配置

    // -------------------------------------------------------------------------
    // from_params(size, params, num_polynomials) — 从协议参数构造。
    //
    // 输入:
    //   size            — 多项式长度 (2 的幂)
    //   params          — ProtocolParameters
    //   num_polynomials — 要承诺的多项式数量
    //
    // 过程: 先构造 BlindingSizePolicy, 再委托给 from_params_with_policy。
    // 输出: ZkConfig
    // -------------------------------------------------------------------------
    static ZkConfig from_params(
        std::size_t size, const ::whir::ProtocolParameters& params,
        std::size_t num_polynomials)
    {
        return from_params_with_policy(size, params, num_polynomials,
            BlindingSizePolicy::from_whir_params(params));
    }

    // 带显式策略的构造 (实现见文件末尾)。
    static ZkConfig from_params_with_policy(
        std::size_t size, const ::whir::ProtocolParameters& params,
        std::size_t num_polynomials, const BlindingSizePolicy& policy);

    // ---- 尺寸参数 ----

    // 见证变量数 = log2(blinded_commitment 的向量长度)
    std::size_t num_witness_variables() const {
        return trailing_zeros(blinded_commitment.initial_size());
    }

    // 盲化变量数 = log2(blinding_commitment 的向量长度) - 1
    // (减 1 是因为盲化向量有 ell+1 个变量, 这里返回 ell)
    std::size_t num_blinding_variables() const {
        return trailing_zeros(blinding_commitment.initial_size()) - 1;
    }

    // 交错深度 = 每个多项式被切分的块数
    std::size_t interleaving_depth() const {
        return blinded_commitment.initial_committer.interleaving_depth;
    }

    // ---- 域生成元 ----

    // 全域生成元: 阶 = codeword_length * interleaving_depth
    // 用于将域内索引映射到 gamma 点
    F omega_full() const {
        std::size_t cw_len = blinded_commitment.initial_committer.codeword_length;
        std::size_t full_domain = cw_len * interleaving_depth();
        auto g = ::whir::algebra::ntt::generator<F>(full_domain);
        assert(g.has_value() && "full_domain 超出 NTT 引擎支持的域大小");
        return *g;
    }

    // 子域生成元: 阶 = codeword_length (NTT 求值域)
    F omega_sub() const {
        return blinded_commitment.initial_committer.generator();
    }

    // zeta = omega_full^codeword_length (coset 偏移)
    F zeta() const {
        std::size_t cw_len = blinded_commitment.initial_committer.codeword_length;
        return omega_full().pow(static_cast<std::uint64_t>(cw_len));
    }

    // omega_sub 的各次幂 [1, ω, ω^2, ..., ω^(cw_len-1)]
    std::vector<F> omega_powers() const {
        std::size_t cw_len = blinded_commitment.initial_committer.codeword_length;
        return ::whir::algebra::geometric_sequence(omega_sub(), cw_len);
    }

    // 在 omega_powers 中查找 alpha_base 的索引。
    // 输入: alpha_base — 域内挑战点; omega_powers — 子域各次幂
    // 输出: 索引 (0 ≤ idx < codeword_length)
    std::size_t query_index(F alpha_base, std::span<const F> omega_powers) const {
        for (std::size_t i = 0; i < omega_powers.size(); ++i)
            if (omega_powers[i] == alpha_base) return i;
        assert(false && "query point must be in IRS domain");
        return 0;
    }

    // all_gammas(query_points) — 对每个域内挑战点展开其 coset。
    //
    // 输入: query_points — 域内挑战点列表 (每个在 {ω^i} 中)
    // 过程: 对每个 alpha:
    //         idx = query_index(alpha)
    //         coset_offset = omega_full^idx
    //         展开为 {coset_offset * zeta^j : j=0..id-1}
    // 输出: gammas — 所有 gamma 点列表 (长度 = query_points.size() * id)
    // =============================================================================
    std::vector<F> all_gammas(std::span<const F> query_points) const {
        auto om_powers = omega_powers();
        std::size_t id = interleaving_depth();
        F om_full = omega_full();
        auto zeta_powers = ::whir::algebra::geometric_sequence(zeta(), id);

        std::vector<F> gammas;
        gammas.reserve(query_points.size() * id);
        for (const auto& alpha : query_points) {
            std::size_t idx = query_index(alpha, om_powers);
            F coset_offset = om_full.pow(static_cast<std::uint64_t>(idx));
            for (const auto& zp : zeta_powers)
                gammas.push_back(coset_offset * zp);
        }
        return gammas;
    }

    // ---- 协议方法 (实现见 whir_zk_impl.hpp) ----

    // commit: 用零知识盲化承诺多项式 (采样盲化, 构造 f_hat, 双重 WHIR 承诺)
    template <typename Transcript, typename Rng>
    ZkWitness<F> commit(Transcript& prover_state,
        std::span<const std::span<const F>> polynomials, Rng& rng) const;

    // receive_commitments: 接收 ZK 承诺 (num_polys 个 f_hat + 1 个 blinding)
    template <typename Transcript>
    ZkCommitment<F> receive_commitments(Transcript& verifier_state,
        std::size_t num_polynomials) const;

    // prove: ZK WHIR 完整证明 (11 步)
    template <typename Transcript, typename Rng>
    ::whir::protocols::whir::FinalClaim<F> prove(
        Transcript& prover_state,
        std::span<const F> vectors_flat,
        ZkWitness<F> witness,
        std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> linear_forms,
        std::span<const F> evaluations,
        Rng& rng) const;

    // verify: ZK WHIR 完整验证 (9 步), 返回 true 表示接受
    template <typename Transcript>
    bool verify(
        Transcript& verifier_state,
        std::span<const ::whir::algebra::LinearForm<F>*> weights,
        std::span<const F> evaluations,
        const ZkCommitment<F>& commitment) const;
};

// =============================================================================
// ZkCommitment<F> — ZK 承诺。
//
// f_hat: 每个多项式的 f_hat 的 WHIR 承诺列表 (长度 = num_polys)
// blinding: 盲化多项式的 WHIR 承诺 (单个, 包含所有盲化向量)
// =============================================================================

template <typename F>
struct ZkCommitment {
    std::vector<::whir::protocols::whir::Commitment<F>> f_hat;
    ::whir::protocols::whir::Commitment<F> blinding;
};

// =============================================================================
// ZkWitness<F> — ZK 见证 (prover 在 commit 后持有)。
//
// f_hat_vectors:    f_hat = f + mask (每个多项式一个)
// f_hat_witnesses:  f_hat 的 IRS Witness (含编码矩阵 + Merkle 见证 + OOD 求值)
// blinding_polynomials: 盲化多项式族 (每个多项式一个 BlindingPolynomials)
// blinding_vectors: 盲化向量的布局 (用于 WHIR 承诺)
// blinding_witness: 盲化向量的 IRS Witness
// =============================================================================

template <typename F>
struct ZkWitness {
    std::vector<std::vector<F>> f_hat_vectors;
    std::vector<::whir::protocols::irs_commit::Witness<F, F>> f_hat_witnesses;
    std::vector<BlindingPolynomials<F>> blinding_polynomials;
    std::vector<std::vector<F>> blinding_vectors;
    ::whir::protocols::irs_commit::Witness<F, F> blinding_witness;
};

// =============================================================================
// ZkConfig::from_params_with_policy — 从参数和策略构造完整配置。
//
// 输入:
//   size            — 多项式长度 (2 的幂)
//   params          — 协议参数
//   num_polynomials — 多项式数量
//   policy          — 盲化大小策略
//
// 过程:
//   1. 构造 blinded_commitment (对原始多项式的 WHIR 配置)
//   2. 计算需要的盲化变量数 num_blinding_vars:
//      上界 q_ub = k1*q_delta_1 + k2*q_delta_2 + t1 + t2 + sumcheck_leak
//      找最小的 num_blinding_vars 使得 2^num_blinding_vars > q_ub
//   3. 构造 blinding_commitment (对盲化多项式的 WHIR 配置)
//      blind_size = 2^num_blinding_vars
//      batch_size = num_polynomials * (num_witness_vars + 1)
//
// 输出: ZkConfig
// =============================================================================

template <typename F>
ZkConfig<F> ZkConfig<F>::from_params_with_policy(
    std::size_t size, const ::whir::ProtocolParameters& params,
    std::size_t num_polynomials, const BlindingSizePolicy& policy)
{
    ZkConfig<F> zk;
    zk.blinded_commitment = WhirConfig::from_params(size, params);

    std::size_t num_witness_vars = trailing_zeros(size);
    std::size_t k1 = std::size_t{1} << zk.blinded_commitment.initial_sumcheck.num_rounds;
    std::size_t k2 = std::size_t{1} << params.initial_folding_factor;
    std::size_t sumcheck_leak = (policy.sumcheck_round_degree + 1) * num_witness_vars;
    std::size_t q_ub = k1 * policy.q_delta_1 + k2 * policy.q_delta_2
                     + policy.t1 + policy.t2 + sumcheck_leak;

    std::size_t num_blinding_vars = 0;
    while ((std::size_t{1} << num_blinding_vars) <= q_ub) ++num_blinding_vars;
    assert(num_blinding_vars < num_witness_vars);

    ::whir::ProtocolParameters blind_params = params;
    blind_params.batch_size = num_polynomials * (num_witness_vars + 1);
    std::size_t blind_size = std::size_t{1} << num_blinding_vars;
    zk.blinding_commitment = WhirConfig::from_params(blind_size, blind_params);

    return zk;
}

} // namespace whir::protocols::whir_zk

// 模板成员函数实现
#include "whir_zk_impl.hpp"
