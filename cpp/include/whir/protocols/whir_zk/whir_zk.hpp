#pragma once

// ============================================================================
// whir_zk.hpp — 零知识 WHIR 协议核心类型定义
//
// ZK WHIR 在 WHIR 基础上扩展零知识性: 证明者证明多项式求值
// 而不泄露多项式本身的值。
//
// 机制:
//   1. 采样随机盲化多项式（BlindingPolynomials）
//   2. 承诺 f_hat = f + mask（mask 是周期性盲化多项式）
//   3. 同时承诺盲化多项式（blinding commitment）
//   4. 运行两个内部 WHIR 实例: 一个用于 f_hat，一个用于 blinding
//   5. 挑战约束强制盲化正确性
//
// 对应 Rust 文件: src/protocols/whir_zk/mod.rs
// ============================================================================

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

// ============================================================================
// BlindingSizePolicy — 控制盲化多项式规模
//
// 参数:
//   q_delta_1, q_delta_2 — 域内查询数的下界（两个安全级别）
//   t1, t2               — 域内查询数（通常 = q_delta_1/2）
//   sumcheck_round_degree — 每轮 sumcheck 次数（默认 3）
//
// 由 ProtocolParameters 通过 from_whir_params() 推导
// ============================================================================

struct BlindingSizePolicy {
    std::size_t q_delta_1 = 0;
    std::size_t q_delta_2 = 0;
    std::size_t t1 = 0;
    std::size_t t2 = 0;
    std::size_t sumcheck_round_degree = 3;

    // 从协议参数构造
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

// ============================================================================
// ZkConfig<F> — ZK WHIR 协议配置
//
// 包含两个内部 WHIR 配置:
//   blinded_commitment  — 用于 f_hat = f + mask 的 WHIR
//   blinding_commitment — 用于盲化多项式本身的 WHIR
//
// 域参数:
//   omega_full() — 完整域生成元（阶 = codeword_length * interleaving_depth）
//   omega_sub()  — 子域生成元（阶 = codeword_length）
//   zeta()       — 陪集偏移 = omega_full^codeword_length
// ============================================================================

template <typename F>
struct ZkConfig {
    using Embedding = ::whir::algebra::Identity<F>;
    using WhirConfig = ::whir::protocols::whir::Config<Embedding>;

    WhirConfig blinded_commitment;   // f_hat 的 WHIR 配置
    WhirConfig blinding_commitment;  // 盲化多项式的 WHIR 配置

    // 从协议参数构造。委托给 from_params_with_policy，自动推导 BlindingSizePolicy
    static ZkConfig from_params(
        std::size_t size, const ::whir::ProtocolParameters& params,
        std::size_t num_polynomials)
    {
        return from_params_with_policy(size, params, num_polynomials,
            BlindingSizePolicy::from_whir_params(params));
    }

    // 使用显式策略构造（实现位于文件末尾）
    static ZkConfig from_params_with_policy(
        std::size_t size, const ::whir::ProtocolParameters& params,
        std::size_t num_polynomials, const BlindingSizePolicy& policy);

    // ---- 尺寸参数 ----

    // witness 变量数 = log2(blinded_commitment.initial_size)
    std::size_t num_witness_variables() const {
        return trailing_zeros(blinded_commitment.initial_size());
    }

    // 盲化变量数 = log2(blinding_commitment.initial_size) - 1
    // -1 是因为盲化向量的 ell+1 变量结构
    std::size_t num_blinding_variables() const {
        return trailing_zeros(blinding_commitment.initial_size()) - 1;
    }

    // 交织深度 = 每个多项式被分割的块数
    std::size_t interleaving_depth() const {
        return blinded_commitment.initial_committer.interleaving_depth;
    }

    // ---- 域生成元 ----

    // 完整域生成元: 阶 = codeword_length * interleaving_depth
    F omega_full() const {
        std::size_t cw_len = blinded_commitment.initial_committer.codeword_length;
        std::size_t full_domain = cw_len * interleaving_depth();
        auto g = ::whir::algebra::ntt::generator<F>(full_domain);
        assert(g.has_value() && "full_domain exceeds NTT engine field size");
        return *g;
    }

    // 子域生成元: 阶 = codeword_length（NTT 求值域）
    F omega_sub() const {
        return blinded_commitment.initial_committer.generator();
    }

    // zeta = omega_full^codeword_length（陪集偏移）
    F zeta() const {
        std::size_t cw_len = blinded_commitment.initial_committer.codeword_length;
        return omega_full().pow(static_cast<std::uint64_t>(cw_len));
    }

    // [1, omega_sub, omega_sub^2, ..., omega_sub^(cw_len-1)]
    std::vector<F> omega_powers() const {
        std::size_t cw_len = blinded_commitment.initial_committer.codeword_length;
        return ::whir::algebra::geometric_sequence(omega_sub(), cw_len);
    }

    // 在 omega_powers 中查找 alpha_base 的索引
    std::size_t query_index(F alpha_base, std::span<const F> omega_powers) const {
        for (std::size_t i = 0; i < omega_powers.size(); ++i)
            if (omega_powers[i] == alpha_base) return i;
        assert(false && "query point must be in IRS domain");
        return 0;
    }

    // 将每个域内挑战点展开为其陪集（interleaving_depth 个 gamma 点）
    //
    // 对每个 alpha: idx = query_index(alpha), coset_offset = omega_full^idx,
    // 然后 {coset_offset * zeta^j : j=0..id-1}
    // 返回所有 gamma 点（长度 = query_points.size() * interleaving_depth）
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

    // ---- 协议方法（实现在 whir_zk_impl.hpp） ----

    // ZK 盲化承诺: 采样盲化，构造 f_hat，双重 WHIR 承诺
    template <typename Transcript, typename Rng>
    ZkWitness<F> commit(Transcript& prover_state,
        std::span<const std::span<const F>> polynomials, Rng& rng) const;

    // 接收 ZK 承诺（num_polys 个 f_hat 承诺 + 1 个 blinding 承诺）
    template <typename Transcript>
    ZkCommitment<F> receive_commitments(Transcript& verifier_state,
        std::size_t num_polynomials) const;

    // ZK WHIR 完整证明（11 步）
    template <typename Transcript, typename Rng>
    ::whir::protocols::whir::FinalClaim<F> prove(
        Transcript& prover_state,
        std::span<const F> vectors_flat,
        ZkWitness<F> witness,
        std::vector<std::unique_ptr<::whir::algebra::LinearForm<F>>> linear_forms,
        std::span<const F> evaluations,
        Rng& rng) const;

    // ZK WHIR 完整验证（9 步）。返回 true 接受
    template <typename Transcript>
    bool verify(
        Transcript& verifier_state,
        std::span<const ::whir::algebra::LinearForm<F>*> weights,
        std::span<const F> evaluations,
        const ZkCommitment<F>& commitment) const;
};

// ============================================================================
// ZkCommitment<F> — ZK 承诺（验证者端）
//
// f_hat:    每个多项式的 WHIR 承诺（长度 = num_polys）
// blinding: 所有盲化向量的单个 WHIR 承诺
// ============================================================================

template <typename F>
struct ZkCommitment {
    std::vector<::whir::protocols::whir::Commitment<F>> f_hat;
    ::whir::protocols::whir::Commitment<F> blinding;
};

// ============================================================================
// ZkWitness<F> — ZK witness（证明者在 commit 后持有）
//
// f_hat_vectors:       f_hat = f + mask（每个多项式一个）
// f_hat_witnesses:     f_hat 的 IRS Witness（RS 矩阵 + Merkle + OOD）
// blinding_polynomials: 每个多项式的 BlindingPolynomials
// blinding_vectors:    盲化向量布局（用于 WHIR 承诺）
// blinding_witness:    盲化向量的 IRS Witness
// ============================================================================

template <typename F>
struct ZkWitness {
    std::vector<std::vector<F>> f_hat_vectors;
    std::vector<::whir::protocols::irs_commit::Witness<F, F>> f_hat_witnesses;
    std::vector<BlindingPolynomials<F>> blinding_polynomials;
    std::vector<std::vector<F>> blinding_vectors;
    ::whir::protocols::irs_commit::Witness<F, F> blinding_witness;
};

// ============================================================================
// ZkConfig::from_params_with_policy — 从参数和策略构造完整 ZK 配置
//
// 流程:
//   1. 构建 blinded_commitment（原始多项式的 WHIR 配置）
//   2. 计算所需盲化变量数:
//      q_ub = k1*q_delta_1 + k2*q_delta_2 + t1 + t2 + sumcheck_leak
//      找最小 num_blinding_vars 使得 2^num_blinding_vars > q_ub
//   3. 构建 blinding_commitment（盲化多项式的 WHIR 配置）:
//      blind_size = 2^num_blinding_vars
//      batch_size = num_polynomials * (num_witness_vars + 1)
// ============================================================================

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
