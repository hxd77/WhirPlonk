#pragma once

// =============================================================================
// whir_zk_utils.hpp -- ZK WHIR 工具函数与数据结构
//
// 提供:
//   BlindingEvaluations<F>  -- 单个 gamma 点的盲化求值结果
//   BlindingPolynomials<F>  -- 盲化多项式族（m_poly + g_hats）
//   embed_to_ell_plus_one   -- 交错零系数嵌入
//   fill_eq_weights_at_gamma / _half -- gamma 处 beq 权重计算
//   fold_weight_to_mask_size -- 将权重折叠到 mask 周期
//   evaluate_gamma_block    -- 在所有 gamma 点上求值盲化多项式
//   combine_claim_from_components -- 通过 tau1 合并 m_claim + g_hat_claims
//   build_combined_and_subproof_claims -- 构建合并声明与子证明声明
//   construct_batched_eq_weights_from_gammas -- 批量 beq 权重构造
//
// 对应 Rust 实现：src/protocols/whir_zk/utils.rs
// =============================================================================

#include "../../algebra/embedding.hpp"
#include "../../algebra/linear_form.hpp"
#include "../../algebra/utilities.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <iterator>
#include <vector>

namespace whir::protocols::whir_zk {

// =============================================================================
// BlindingEvaluations<F> -- 单个 gamma 点的盲化求值结果
//
// 字段:
//   gamma       -- 求值点
//   m_eval      -- M(gamma, -rho) = <beq_full, m_poly>
//   g_hat_evals -- g_hat_j(gamma, -rho), j=0..mu-1
//
// compute_h_value(blinding_challenge):
//   h = m_eval + SUM_j beta^j * gamma^(2^(j-1)) * g_hat_eval_j
//   其中 beta = blinding_challenge
//
// 验证者使用此结构本地重算期望的 h 值，并与证明者的声明比较。
// 不一致意味着作弊或盲化多项式不一致。
// =============================================================================

template <typename F>
struct BlindingEvaluations {
    F gamma;
    F m_eval;                         // M(gamma, -rho)
    std::vector<F> g_hat_evals;       // g_hat_j(gamma, -rho), j=0..mu-1

    // 重算 h = m_eval + SUM_j beta^j * gamma^(2^(j-1)) * g_hat_eval_j
    // 迭代过程: beta_pow 累积 beta; gamma_pow 每步平方
    // (gamma, gamma^2, gamma^4, ...)
    F compute_h_value(F blinding_challenge) const {
        F value = m_eval;
        F blind_pow = blinding_challenge;
        F gamma_pow = gamma;
        for (const auto& g_hat : g_hat_evals) {
            value += blind_pow * gamma_pow * g_hat;
            blind_pow *= blinding_challenge;
            gamma_pow = gamma_pow.square();
        }
        return value;
    }
};

// =============================================================================
// embed_to_ell_plus_one -- 将 ell 变量系数嵌入到 ell+1 变量
//
// 输入:  长度为 2^ell 的 coeffs
// 输出:  长度为 2^(ell+1)，其中 output[2i] = coeffs[i], output[2i+1] = 0
//
// 这是"交错零"嵌入: 多线性多项式扩展到多一个变量，该变量的系数全为零。
// 用于将盲化多项式 g_hat 从 ell 变量域提升到 ell+1 变量域。
// =============================================================================

template <typename F>
std::vector<F> embed_to_ell_plus_one(std::span<const F> coeffs) {
    std::vector<F> result(coeffs.size() * 2, F::zero());
    for (std::size_t i = 0; i < coeffs.size(); ++i)
        result[2 * i] = coeffs[i];
    return result;
}

// =============================================================================
// BlindingPolynomials<F> -- 盲化多项式族
//
// 结构:
//   m_poly -- 交织盲化多项式（长度 2^(ell+1)）:
//             [g0_hat[0], msk[0], g0_hat[1], msk[1], ...]
//             其中 g0_hat 和 msk 各长 2^ell
//   g_hats -- 每个 witness 变量对应的盲化多项式（mu 个，各长 2^ell）
//
// 交织布局使得 beq 恒等式成立:
//   <beq_full, m_poly> = SUM_j half[j] * ((1+rho)*m_poly[2j] + (-rho)*m_poly[2j+1])
// 从而可以仅用半尺寸 beq 权重计算 m_eval。
// =============================================================================

template <typename F>
struct BlindingPolynomials {
    // m_poly: 交织布局 [g0_hat[0], msk[0], g0_hat[1], msk[1], ...]，长度 2^(ell+1)
    std::vector<F> m_poly;

    // g_hats[j]: 每个 witness 变量的盲化多项式，长度 2^ell
    std::vector<std::vector<F>> g_hats;

    // -------------------------------------------------------------------------
    // 随机采样所有盲化多项式
    //
    // rng                     -- 随机数生成器
    // num_blinding_variables  -- ell，盲化变量数
    // num_witness_variables   -- mu，witness 变量数
    //
    // 1. half_size = 2^ell: 采样 msk[half_size], g0_hat[half_size]
    // 2. 交织: m_poly[2i]=g0_hat[i], m_poly[2i+1]=msk[i]
    // 3. 对 j=0..mu-1: 采样 g_hats[j][half_size]
    // -------------------------------------------------------------------------
    template <typename Rng>
    static BlindingPolynomials sample(
        Rng& rng,
        std::size_t num_blinding_variables,
        std::size_t num_witness_variables)
    {
        std::size_t half_size = std::size_t{1} << num_blinding_variables;

        std::vector<F> msk(half_size);
        std::vector<F> g0_hat(half_size);
        for (std::size_t i = 0; i < half_size; ++i) {
            msk[i] = F::random(rng);
            g0_hat[i] = F::random(rng);
        }

        // 交织: [g0_hat[0], msk[0], g0_hat[1], msk[1], ...]
        std::vector<F> m_poly(2 * half_size);
        for (std::size_t i = 0; i < half_size; ++i) {
            m_poly[2 * i] = g0_hat[i];
            m_poly[2 * i + 1] = msk[i];
        }

        // 每个 witness 变量的盲化多项式
        std::vector<std::vector<F>> g_hats(num_witness_variables);
        for (std::size_t j = 0; j < num_witness_variables; ++j) {
            g_hats[j].resize(half_size);
            for (auto& v : g_hats[j]) v = F::random(rng);
        }

        return {std::move(m_poly), std::move(g_hats)};
    }

    // -------------------------------------------------------------------------
    // 展平为 WHIR 承诺向量布局
    //
    // 返回 [M, g_hat_0^emb, ..., g_hat_{mu-1}^emb]
    //   M = m_poly（长度 2^(ell+1)）
    //   g_hat_j^emb = embed_to_ell_plus_one(g_hats[j])（长度 2^(ell+1)）
    //
    // 共计 mu+1 个向量，各长 2^(ell+1)，用于 blinding_commitment
    // -------------------------------------------------------------------------
    std::vector<std::vector<F>> layout_vectors() const {
        std::vector<std::vector<F>> result;
        result.reserve(1 + g_hats.size());
        result.push_back(m_poly);
        auto embedded = embedded_g_hats();
        result.insert(result.end(),
            std::make_move_iterator(embedded.begin()),
            std::make_move_iterator(embedded.end()));
        return result;
    }

    // 将所有 g_hats 嵌入到 ell+1 变量（交错零）
    std::vector<std::vector<F>> embedded_g_hats() const {
        std::vector<std::vector<F>> result;
        result.reserve(g_hats.size());
        for (const auto& gh : g_hats)
            result.push_back(embed_to_ell_plus_one<F>(gh));
        return result;
    }
};

// =============================================================================
// fill_eq_weights_at_gamma -- 在 gamma 处计算完整 beq 权重（ell+1 变量）
//
// buf                    -- 输出缓冲区（长度 >= 2^(ell+1)）
// gamma                  -- 求值点
// masking_challenge (rho) -- masking 挑战
// num_blinding_variables -- ell
//
// 用 beq((gamma, -rho), .) 的求值填充 buf
//
// 算法（迭代张量展开）:
//   buf[0] = 1
//   对变量 i = 0..ell-1（基 = gamma, gamma^2, gamma^4, ...）:
//     buf[2j+1] = buf[j] * gamma_power    (bit = 1)
//     buf[2j]   = buf[j] - buf[2j+1]      (bit = 0)
//   对最后一个变量 (ell):
//     buf[2j+1] = buf[j] * (-rho)         (bit = 1)
//     buf[2j]   = buf[j] - buf[2j+1]      (bit = 0)
//
// 结果: buf[i] = PRODUCT_k beq_component(k, i_bit_k)
//   其中 beq_component(k, 0) = 1 - x_k, beq_component(k, 1) = x_k
//   x = (gamma, gamma^2, ..., gamma^(2^(ell-1)), -rho)
// =============================================================================

template <typename F>
void fill_eq_weights_at_gamma(
    std::span<F> buf,
    F gamma,
    F masking_challenge,
    std::size_t num_blinding_variables)
{
    std::size_t num_total = num_blinding_variables + 1;
    std::size_t size = std::size_t{1} << num_total;
    assert(buf.size() >= size);

    std::fill_n(buf.data(), size, F::zero());
    buf[0] = F::one();

    // 变量 0..ell-1: 平方梯度基
    F gamma_power = gamma;
    for (std::size_t i = 0; i < num_blinding_variables; ++i) {
        std::size_t half = std::size_t{1} << i;
        for (std::size_t j = half; j > 0; --j) {
            std::size_t jj = j - 1;
            buf[2 * jj + 1] = buf[jj] * gamma_power;
            buf[2 * jj] = buf[jj] - buf[2 * jj + 1];
        }
        gamma_power = gamma_power.square();
    }

    // 最后一个变量 (ell): 固定为 -masking_challenge
    F neg_rho = -masking_challenge;
    std::size_t half = std::size_t{1} << num_blinding_variables;
    for (std::size_t j = half; j > 0; --j) {
        std::size_t jj = j - 1;
        buf[2 * jj + 1] = buf[jj] * neg_rho;
        buf[2 * jj] = buf[jj] - buf[2 * jj + 1];
    }
}

// =============================================================================
// fill_eq_weights_at_gamma_half -- 半尺寸 beq 权重（仅 ell 变量，无 -rho）
//
// buf                    -- 输出缓冲区（长度 >= 2^ell）
// gamma                  -- 求值点
// num_blinding_variables -- ell
//
// 用 beq 的前 ell 个变量在 (gamma, gamma^2, ...) 处的求值填充 buf
//
// 与完整版本的关系（用于 evaluate_gamma_block）:
//   full[2j]   = half[j] * (1 + rho)
//   full[2j+1] = half[j] * (-rho)
// 此恒等式使得高效计算 m_eval 成为可能:
//   m_eval = <beq_full, m_poly>
//          = SUM_j half[j] * ((1+rho)*m_poly[2j] + (-rho)*m_poly[2j+1])
// =============================================================================

template <typename F>
void fill_eq_weights_at_gamma_half(
    std::span<F> buf,
    F gamma,
    std::size_t num_blinding_variables)
{
    std::size_t size = std::size_t{1} << num_blinding_variables;
    assert(buf.size() >= size);

    std::fill_n(buf.data(), size, F::zero());
    buf[0] = F::one();

    F gamma_power = gamma;
    for (std::size_t i = 0; i < num_blinding_variables; ++i) {
        std::size_t half = std::size_t{1} << i;
        for (std::size_t j = half; j > 0; --j) {
            std::size_t jj = j - 1;
            buf[2 * jj + 1] = buf[jj] * gamma_power;
            buf[2 * jj] = buf[jj] - buf[2 * jj + 1];
        }
        gamma_power = gamma_power.square();
    }
}

// =============================================================================
// fold_weight_to_mask_size -- 将线性形式折叠到盲化周期
//
// weight                 -- 任意线性形式（长度 = 2^num_witness_variables）
// num_witness_variables  -- witness 变量数
// num_blinding_variables -- 盲化变量数
//
// 返回长度为 2^(ell+1) 的 w_folded，其中:
//   w_folded[j] = SUM_{i = j (mod P)} weight[i]
//   P = 2^(ell+1)（盲化周期）
//
// 原理: 盲化多项式以 P 为周期，因此验证者只需折叠后的权重即可验证求值。
// 信息无损失，因为每个周期内的多项式结构是已知的。
// =============================================================================

template <typename F>
std::vector<F> fold_weight_to_mask_size(
    const ::whir::algebra::LinearForm<F>& weight,
    std::size_t num_witness_variables,
    std::size_t num_blinding_variables)
{
    std::size_t mask_size = std::size_t{1} << (num_blinding_variables + 1);

    // 将 LinearForm 具化为 Covector（系数向量）
    auto cv = ::whir::algebra::Covector<F>::from_linear_form(weight);
    assert(cv.vector.size() == (std::size_t{1} << num_witness_variables));

    // 按 mask_size 周期折叠
    std::vector<F> folded(mask_size, F::zero());
    for (std::size_t i = 0; i < cv.vector.size(); ++i)
        folded[i % mask_size] += cv.vector[i];

    return folded;
}

// =============================================================================
// evaluate_gamma_block -- 在所有 gamma 点上求值盲化多项式
//
// blinding_polys         -- 每个多项式的盲化多项式族
// h_gammas               -- gamma 点（域内挑战的陪集展开）
// masking_challenge (rho) -- masking 挑战
// blinding_challenge (beta) -- blinding 挑战
// tau2                   -- 批处理参数
// num_blinding_variables -- ell
// num_witness_variables  -- mu
//
// 返回 pair<vector<F>, vector<F>>:
//   .first  = eval_results
//     布局: [m_eval, g_hat_0, ..., g_hat_{mu-1}, h_val] x num_polys，每 gamma 一组
//     m_eval  = <eq_half, folded_m_poly>           （半尺寸点积）
//     g_hat_j = (1+rho) * <eq_half, g_hats[j]>    （半尺寸点积）
//     h_val   = m_eval + SUM_j beta^j * gamma^(2^(j-1)) * g_hat_j
//   .second = beq_weight_accum
//     从半尺寸累加器重构的完整尺寸 beq 权重:
//     full[2j] = half[j]*(1+rho), full[2j+1] = half[j]*(-rho)
//
// 优化: 使用半尺寸 beq 权重（fill_eq_weights_at_gamma_half）避免完整尺寸计算，
// 然后通过 beq 恒等式重构。
// =============================================================================

template <typename F>
std::pair<std::vector<F>, std::vector<F>> evaluate_gamma_block(
    const std::vector<BlindingPolynomials<F>>& blinding_polys,
    std::span<const F> h_gammas,
    F masking_challenge,
    F blinding_challenge,
    F tau2,
    std::size_t num_blinding_variables,
    std::size_t num_witness_variables)
{
    std::size_t num_polys = blinding_polys.size();
    std::size_t half_size = std::size_t{1} << num_blinding_variables;
    std::size_t weight_size = std::size_t{1} << (num_blinding_variables + 1);

    F one_plus_rho = F::one() + masking_challenge;
    F neg_rho = -masking_challenge;

    // 预折叠 m_poly: 利用 beq 恒等式将完整尺寸点积转换为半尺寸
    // folded_m[pi][j] = (1+rho) * m_poly[2j] + (-rho) * m_poly[2j+1]
    std::vector<std::vector<F>> folded_m_polys(num_polys);
    for (std::size_t pi = 0; pi < num_polys; ++pi) {
        const auto& bp = blinding_polys[pi];
        folded_m_polys[pi].resize(half_size);
        for (std::size_t j = 0; j < half_size; ++j) {
            folded_m_polys[pi][j] =
                one_plus_rho * bp.m_poly[2 * j] + neg_rho * bp.m_poly[2 * j + 1];
        }
    }

    // 预计算 tau2 幂次: [1, tau2, tau2^2, ...]
    std::size_t num_gammas = h_gammas.size();
    std::vector<F> tau2_powers(num_gammas);
    {
        F p = F::one();
        for (std::size_t i = 0; i < num_gammas; ++i) {
            tau2_powers[i] = p;
            p *= tau2;
        }
    }

    // eval_results 布局: 每 gamma x 每多项式 x (mu + 2 个域元素)
    std::size_t stride_per_poly = num_witness_variables + 2;
    std::size_t stride_per_gamma = num_polys * stride_per_poly;
    std::vector<F> eval_results(num_gammas * stride_per_gamma, F::zero());

    // beq 权重累加器（半尺寸）
    std::vector<F> beq_half_accum(half_size, F::zero());
    std::vector<F> eq_buf(half_size);

    ::whir::algebra::Identity<F> identity;

    for (std::size_t gi = 0; gi < num_gammas; ++gi) {
        F gamma = h_gammas[gi];
        F tau2_pow = tau2_powers[gi];

        // 计算半尺寸 beq 权重
        fill_eq_weights_at_gamma_half<F>(eq_buf, gamma, num_blinding_variables);

        // 累积 beq 权重（半尺寸，tau2 加权批处理）
        ::whir::algebra::scalar_mul_add<F>(beq_half_accum, tau2_pow, eq_buf);

        F* slot = eval_results.data() + gi * stride_per_gamma;
        for (std::size_t pi = 0; pi < num_polys; ++pi) {
            F* off = slot + pi * stride_per_poly;

            // m_eval = <eq_buf, folded_m_poly>（半尺寸点积）
            off[0] = F::zero();
            for (std::size_t j = 0; j < half_size; ++j)
                off[0] += eq_buf[j] * folded_m_polys[pi][j];

            // g_hat_evals[j] = (1+rho) * <eq_buf, g_hats[j]>
            for (std::size_t j = 0; j < num_witness_variables; ++j) {
                off[1 + j] = one_plus_rho *
                    ::whir::algebra::mixed_dot<::whir::algebra::Identity<F>>(
                        identity, eq_buf, blinding_polys[pi].g_hats[j]);
            }

            // h_val = m_eval + SUM_j beta^j * gamma^(2^(j-1)) * g_hat_eval_j
            F h = off[0];
            F bp_pow = blinding_challenge;
            F gp = gamma;
            for (std::size_t j = 0; j < num_witness_variables; ++j) {
                h += bp_pow * gp * off[1 + j];
                bp_pow *= blinding_challenge;
                gp = gp.square();
            }
            off[1 + num_witness_variables] = h;
        }
    }

    // 从半尺寸累加器重构完整尺寸 beq_weight_accum
    std::vector<F> beq_weight_accum(weight_size, F::zero());
    for (std::size_t j = 0; j < half_size; ++j) {
        beq_weight_accum[2 * j] = one_plus_rho * beq_half_accum[j];
        beq_weight_accum[2 * j + 1] = neg_rho * beq_half_accum[j];
    }

    return {std::move(eval_results), std::move(beq_weight_accum)};
}

// =============================================================================
// combine_claim_from_components -- 通过 tau1 合并 (m_claim, g_hat_claims)
//
// m_claim       -- M 的声明值
// g_hat_claims  -- g_hat_j 的声明值（长度 = num_witness_variables）
// tau1          -- 合并随机标量
//
// 返回: C(tau1) = m_claim + 2 * tau1 * SUM_j tau1^j * g_hat_claims[j]
//
// 因子 2 补偿 g_hat 的交错零嵌入: 由于 g_hat 仅占据偶数位置，
// 内积减半，因此合并时需要此二倍因子。
// =============================================================================

template <typename F>
F combine_claim_from_components(F m_claim, std::span<const F> g_hat_claims, F tau1) {
    F g_hat_sum = F::zero();
    F tau1_pow = F::one();
    for (const auto& g : g_hat_claims) {
        g_hat_sum += tau1_pow * g;
        tau1_pow *= tau1;
    }
    return m_claim + (F::one() + F::one()) * tau1 * g_hat_sum; // 2 * tau1
}

// =============================================================================
// build_combined_and_subproof_claims -- 构建合并声明与子证明声明
//
// m_claims              -- 每个多项式的 M 声明
// g_hat_claims_per_poly -- 每个多项式的 g_hat 声明列表
// tau1                  -- 合并参数
//
// 返回 pair<vector<F>, vector<F>>:
//   .first  = combined_claims[i] = combine_claim(m_claims[i], g_hat_claims_per_poly[i], tau1)
//   .second = subproof_claims（展平的 [m_claims, g_hat_claims...]）
//             布局: [m_0, g_hat_0[0..mu], m_1, g_hat_1[0..mu], ...]
//
// subproof_claims 作为 blinding 侧 WHIR 的声明输入
// =============================================================================

template <typename F>
std::pair<std::vector<F>, std::vector<F>> build_combined_and_subproof_claims(
    std::span<const F> m_claims,
    const std::vector<std::span<const F>>& g_hat_claims_per_poly,
    F tau1)
{
    std::size_t num_polys = m_claims.size();
    std::size_t num_witness_vars = g_hat_claims_per_poly.empty()
        ? 0 : g_hat_claims_per_poly[0].size();

    std::vector<F> combined_claims(num_polys);
    std::vector<F> subproof_claims;
    subproof_claims.reserve(num_polys * (1 + num_witness_vars));

    for (std::size_t i = 0; i < num_polys; ++i) {
        subproof_claims.push_back(m_claims[i]);
        auto g_slice = g_hat_claims_per_poly[i];
        subproof_claims.insert(subproof_claims.end(), g_slice.begin(), g_slice.end());
        combined_claims[i] = combine_claim_from_components(
            m_claims[i], g_slice, tau1);
    }

    return {std::move(combined_claims), std::move(subproof_claims)};
}

// =============================================================================
// construct_batched_eq_weights_from_gammas -- 从 gamma 点批量构造 beq 权重
//
// gammas                 -- gamma 点
// masking_challenge (rho) -- masking 挑战
// tau2                   -- 批处理参数
// num_blinding_variables -- ell
//
// 对每个 gamma_i，计算 fill_eq_weights_at_gamma（完整，ell+1 变量），
// 然后以 tau2^i 加权累积
//
// 返回长度为 2^(ell+1) 的 Covector<F>:
//   = SUM_i tau2^i * beq((pow(gamma_i), -rho), .)
//
// 用于 blinding 侧 WHIR 的 beq 权重约束验证
// =============================================================================

template <typename F>
::whir::algebra::Covector<F> construct_batched_eq_weights_from_gammas(
    std::span<const F> gammas,
    F masking_challenge,
    F tau2,
    std::size_t num_blinding_variables)
{
    std::size_t weight_size = std::size_t{1} << (num_blinding_variables + 1);

    std::vector<F> weight_evals(weight_size, F::zero());
    std::vector<F> buf(weight_size);
    F batching_power = F::one();

    for (const auto& gamma : gammas) {
        fill_eq_weights_at_gamma<F>(buf, gamma, masking_challenge, num_blinding_variables);
        ::whir::algebra::scalar_mul_add<F>(weight_evals, batching_power, buf);
        batching_power *= tau2;
    }

    return ::whir::algebra::Covector<F>(std::move(weight_evals));
}

} // namespace whir::protocols::whir_zk
