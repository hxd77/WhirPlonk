#pragma once

// =============================================================================
// whir_zk_utils.hpp — ZK WHIR 核心工具函数和数据结构。
// 对应 WHIR 中的 src/protocols/whir_zk/utils.rs。
//
// 提供:
//   BlindingEvaluations<F> — 单个 gamma 点的盲化求值结果
//   BlindingPolynomials<F> — 盲化多项式族 (m_poly + g_hats)
//   embed_to_ell_plus_one  — 系数交错零扩展 (ell → ell+1 变量)
//   fill_eq_weights_at_gamma / _half — 在 gamma 处填充 beq 权重
//   fold_weight_to_mask_size — 折叠权重到盲化周期
//   evaluate_gamma_block  — 在所有 gamma 点求值盲化多项式
//   combine_claim_from_components — 用 tau1 合并 m_claim 和 g_hat_claims
//   build_combined_and_subproof_claims — 构造合并声明和子证明声明
//   construct_batched_eq_weights_from_gammas — 批量构造 beq 权重
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
// BlindingEvaluations<F> — 单个 gamma 点处的盲化求值。
//
// 字段:
//   gamma       — 求值点
//   m_eval      — M(gamma, -rho) = ⟨beq_full, m_poly⟩
//   g_hat_evals — g_hat_j(gamma, -rho) per j (每个见证变量一个)
//
// compute_h_value(blinding_challenge) — 计算组合值:
//   h = m_eval + Σ_j β^j * gamma^(2^(j-1)) * g_hat_eval_j
// 其中 β = blinding_challenge, 这是 ZK 验证的核心一致性检查。
// =============================================================================

template <typename F>
struct BlindingEvaluations {
    F gamma;
    F m_eval;                         // M(gamma, -rho)
    std::vector<F> g_hat_evals;       // g_hat_j(gamma, -rho), j=0..mu-1

    // 输入: blinding_challenge (β)
    // 输出: h = m_eval + Σ β^j * gamma^(2^(j-1)) * g_hat_eval_j
    //
    // 递推: β_pow 每次乘 β; gamma_pow 每次平方 (gamma, gamma^2, gamma^4, ...)
    //
    // 验证者用此函数本地计算期望值, 与 prover 发送的值比对。
    // 若不一致 → prover 作弊或盲化多项式不一致。
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
// embed_to_ell_plus_one — 将 ell 变量的系数嵌入到 ell+1 变量。
//
// 输入: coeffs — 长度 2^ell 的系数数组
// 输出: 长度 2^(ell+1) 的数组, 其中 output[2i] = coeffs[i], output[2i+1] = 0
//
// 这是"交错零"嵌入: 把多线性多项式从 ell 变量扩展到 ell+1 变量,
// 新增变量的系数全为零 (即多项式不依赖新变量)。
// 用于将盲化多项式 g_hat 从 ell 变量提升到 ell+1 变量域。
//
// 例子: [c0, c1, c2, c3] → [c0, 0, c1, 0, c2, 0, c3, 0]
// =============================================================================

template <typename F>
std::vector<F> embed_to_ell_plus_one(std::span<const F> coeffs) {
    std::vector<F> result(coeffs.size() * 2, F::zero());
    for (std::size_t i = 0; i < coeffs.size(); ++i)
        result[2 * i] = coeffs[i];
    return result;
}

// =============================================================================
// BlindingPolynomials<F> — 盲化多项式族。
//
// 结构:
//   m_poly — 交错排列的盲化多项式 (长度 2^(ell+1)):
//            [g0_hat[0], msk[0], g0_hat[1], msk[1], ...]
//            其中 g0_hat 和 msk 各长 2^ell, 交错后长 2^(ell+1)
//   g_hats — 每个见证变量的盲化多项式 (共 mu 个, 每个长 2^ell)
//
// sample(rng, num_blinding_variables, num_witness_variables):
//   随机采样所有盲化多项式。
//   m_poly 的设计使得 g0_hat = m_poly[2i], msk = m_poly[2i+1],
//   从而 m = (1+rho) * g0_hat + (-rho) * msk 产生零知识掩盖。
//
// layout_vectors() → [m_poly, g_hat_0_emb, ..., g_hat_{mu-1}_emb]
//   用于 WHIR 承诺的向量布局。
// =============================================================================

template <typename F>
struct BlindingPolynomials {
    // m_poly: 交错 [g0_hat[0], msk[0], g0_hat[1], msk[1], ...], 长 2^(ell+1)
    std::vector<F> m_poly;

    // g_hats[j]: 每个见证变量 j 的盲化多项式, 长 2^ell
    std::vector<std::vector<F>> g_hats;

    // -------------------------------------------------------------------------
    // sample(rng, num_blinding_variables, num_witness_variables)
    //   — 随机采样盲化多项式族。
    //
    // 输入:
    //   rng                     — 随机数生成器
    //   num_blinding_variables  — ell, 盲化变量数
    //   num_witness_variables   — mu, 见证变量数
    //
    // 过程:
    //   1. half_size = 2^ell: 随机采样 msk[half_size], g0_hat[half_size]
    //   2. 交错: m_poly[2i]=g0_hat[i], m_poly[2i+1]=msk[i]
    //   3. 对 j=0..mu-1: 随机采样 g_hats[j][half_size]
    //
    // 输出: BlindingPolynomials
    // =========================================================================
    template <typename Rng>
    static BlindingPolynomials sample(
        Rng& rng,
        std::size_t num_blinding_variables,
        std::size_t num_witness_variables)
    {
        std::size_t half_size = std::size_t{1} << num_blinding_variables;

        // 随机采样 msk 和 g0_hat
        std::vector<F> msk(half_size);
        std::vector<F> g0_hat(half_size);
        for (std::size_t i = 0; i < half_size; ++i) {
            msk[i] = F::random(rng);
            g0_hat[i] = F::random(rng);
        }

        // 交错: [g0_hat[0], msk[0], g0_hat[1], msk[1], ...]
        std::vector<F> m_poly(2 * half_size);
        for (std::size_t i = 0; i < half_size; ++i) {
            m_poly[2 * i] = g0_hat[i];
            m_poly[2 * i + 1] = msk[i];
        }

        // 每个见证变量的盲化多项式
        std::vector<std::vector<F>> g_hats(num_witness_variables);
        for (std::size_t j = 0; j < num_witness_variables; ++j) {
            g_hats[j].resize(half_size);
            for (auto& v : g_hats[j]) v = F::random(rng);
        }

        return {std::move(m_poly), std::move(g_hats)};
    }

    // -------------------------------------------------------------------------
    // layout_vectors() — 展平为 WHIR 承诺的向量布局。
    //
    // 输出: [M, g_hat_1^emb, ..., g_hat_mu^emb]
    //       M = m_poly (长 2^(ell+1))
    //       g_hat_j^emb = embed_to_ell_plus_one(g_hats[j]) (长 2^(ell+1))
    //
    // 共 mu+1 个向量, 每个长度 2^(ell+1), 用于 WHIR 的 blind_commitment。
    // =========================================================================
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

    // 将所有 g_hat 嵌入到 ell+1 变量 (交错零)。
    std::vector<std::vector<F>> embedded_g_hats() const {
        std::vector<std::vector<F>> result;
        result.reserve(g_hats.size());
        for (const auto& gh : g_hats)
            result.push_back(embed_to_ell_plus_one<F>(gh));
        return result;
    }
};

// =============================================================================
// fill_eq_weights_at_gamma — 在 gamma 处填充完整 beq 权重 (ell+1 个变量)。
//
// 输入:
//   buf                    — 输出缓冲 (长度 ≥ 2^(num_blinding_variables + 1))
//   gamma                  — 求值点
//   masking_challenge (rho)— 掩码挑战值
//   num_blinding_variables — ell (盲化变量数)
//
// 输出: buf 填充为 beq((gamma, -rho), .) 的求值表示
//
// 算法 (迭代张量展开):
//   buf[0] = 1
//   对变量 i = 0..ell-1 (basis = gamma, gamma^2, gamma^4, ...):
//     buf[2j+1] = buf[j] * gamma_power    (分量 = 1)
//     buf[2j]   = buf[j] - buf[2j+1]      (分量 = 0)
//   对最后一个变量 (ell):
//     buf[2j+1] = buf[j] * (-rho)         (分量 = 1)
//     buf[2j]   = buf[j] - buf[2j+1]      (分量 = 0)
//
// 结果: buf[i] = Π_k beq_component(k, i_bit_k)
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

    // 变量 0..ell-1: 平方梯 basis
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
// fill_eq_weights_at_gamma_half — 半尺寸 beq 权重 (仅 ell 个变量, 无 -rho)。
//
// 输入:
//   buf                    — 输出缓冲 (长度 ≥ 2^num_blinding_variables)
//   gamma                  — 求值点
//   num_blinding_variables — ell
//
// 输出: buf 填充为前 ell 个变量的 beq 权重 (在 gamma, gamma^2, ... 处)
//
// 与全尺寸版本的关系:
//   full[2j]   = half[j] * (1 + rho)
//   full[2j+1] = half[j] * (-rho)
// 这个恒等式在 evaluate_gamma_block 中用于高效计算 m_eval:
//   m_eval = ⟨beq_full, m_poly⟩ = Σ_j half[j] * ((1+rho)*m_poly[2j] + (-rho)*m_poly[2j+1])
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
// fold_weight_to_mask_size — 折叠权重到盲化周期。
//
// 输入:
//   weight                 — 任意线性形式 (长度 = 2^num_witness_variables)
//   num_witness_variables  — 见证变量数
//   num_blinding_variables — 盲化变量数
//
// 输出: w_folded (长度 = 2^(num_blinding_variables + 1))
//       w_folded[j] = Σ_{i ≡ j (mod P)} weight[i]
//       其中 P = 2^(num_blinding_variables + 1)
//
// 用途: 盲化多项式是周期性的 (周期 P), 所以验证者只需要折叠后的权重
//       即可验证求值。折叠不丢失信息因为原权重在周期内的结构已知。
// =============================================================================

template <typename F>
std::vector<F> fold_weight_to_mask_size(
    const ::whir::algebra::LinearForm<F>& weight,
    std::size_t num_witness_variables,
    std::size_t num_blinding_variables)
{
    std::size_t mask_size = std::size_t{1} << (num_blinding_variables + 1);

    // 将 LinearForm 物化为 Covector (系数向量)
    auto cv = ::whir::algebra::Covector<F>::from_linear_form(weight);
    assert(cv.vector.size() == (std::size_t{1} << num_witness_variables));

    // 按 mask_size 周期折叠
    std::vector<F> folded(mask_size, F::zero());
    for (std::size_t i = 0; i < cv.vector.size(); ++i)
        folded[i % mask_size] += cv.vector[i];

    return folded;
}

// =============================================================================
// evaluate_gamma_block — 在所有 gamma 点求值盲化多项式并累积 beq 权重。
//
// 输入:
//   blinding_polys         — 每个多项式的盲化多项式族
//   h_gammas               — gamma 点列表 (每个域内挑战点的 coset 展开)
//   masking_challenge (rho)— 掩码挑战
//   blinding_challenge (β) — 盲化挑战
//   tau2                   — 批量化参数
//   num_blinding_variables — ell
//   num_witness_variables  — mu
//
// 输出: pair<vector<F>, vector<F>>
//   .first  = eval_results
//     布局: [m_eval, g_hat_0, ..., g_hat_{mu-1}, h_val] × num_polys per gamma
//     m_eval     = ⟨eq_half, folded_m_poly⟩
//     g_hat_j    = (1+rho) * ⟨eq_half, g_hats[j]⟩
//     h_val      = m_eval + Σ β^j * gamma^(2^(j-1)) * g_hat_j
//   .second = beq_weight_accum
//     全尺寸 beq 权重累积 (从半尺寸重建: full[2j]=half[j]*(1+rho), full[2j+1]=half[j]*(-rho))
//
// 优化: 使用半尺寸 beq 权重 (fill_eq_weights_at_gamma_half) 避免全尺寸计算,
//       然后利用 beq 恒等式重建全尺寸结果。
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

    // 预折叠 m_poly: 对每个多项式, 用 beq 恒等式把全尺寸点积化为半尺寸
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

    // eval_results 布局: 每个 gamma × 每个 poly × (mu + 2 个字段)
    std::size_t stride_per_poly = num_witness_variables + 2;
    std::size_t stride_per_gamma = num_polys * stride_per_poly;
    std::vector<F> eval_results(num_gammas * stride_per_gamma, F::zero());

    // beq 权重累积器 (半尺寸)
    std::vector<F> beq_half_accum(half_size, F::zero());
    std::vector<F> eq_buf(half_size);

    ::whir::algebra::Identity<F> identity;

    for (std::size_t gi = 0; gi < num_gammas; ++gi) {
        F gamma = h_gammas[gi];
        F tau2_pow = tau2_powers[gi];

        // 计算半尺寸 beq 权重
        fill_eq_weights_at_gamma_half<F>(eq_buf, gamma, num_blinding_variables);

        // 累积 beq 权重 (半尺寸, 用 tau2 批量化)
        ::whir::algebra::scalar_mul_add<F>(beq_half_accum, tau2_pow, eq_buf);

        F* slot = eval_results.data() + gi * stride_per_gamma;
        for (std::size_t pi = 0; pi < num_polys; ++pi) {
            F* off = slot + pi * stride_per_poly;

            // m_eval = ⟨eq_buf, folded_m_poly⟩  (半尺寸点积)
            off[0] = F::zero();
            for (std::size_t j = 0; j < half_size; ++j)
                off[0] += eq_buf[j] * folded_m_polys[pi][j];

            // g_hat_evals[j] = (1+rho) * ⟨eq_buf, g_hats[j]⟩
            for (std::size_t j = 0; j < num_witness_variables; ++j) {
                off[1 + j] = one_plus_rho *
                    ::whir::algebra::mixed_dot<::whir::algebra::Identity<F>>(
                        identity, eq_buf, blinding_polys[pi].g_hats[j]);
            }

            // h_val = m_eval + Σ β^j * gamma^(2^(j-1)) * g_hat_eval_j
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

    // 从半尺寸累积器重建全尺寸 beq_weight_accum
    std::vector<F> beq_weight_accum(weight_size, F::zero());
    for (std::size_t j = 0; j < half_size; ++j) {
        beq_weight_accum[2 * j] = one_plus_rho * beq_half_accum[j];
        beq_weight_accum[2 * j + 1] = neg_rho * beq_half_accum[j];
    }

    return {std::move(eval_results), std::move(beq_weight_accum)};
}

// =============================================================================
// combine_claim_from_components — 用 tau1 将 (m_claim, g_hat_claims) 合并。
//
// 输入:
//   m_claim       — M 的声明值
//   g_hat_claims  — g_hat_j 的声明值列表 (长度 = num_witness_variables)
//   tau1          — 合并随机标量
//
// 输出: C(tau1) = m_claim + 2 * tau1 * Σ_j tau1^j * g_hat_claims[j]
//
// 因子 2 的来源: g_hat 嵌入到 ell+1 变量时做了穿插零,
// 导致内积减半 (只有偶位置有值)。合并时需要补偿这个 2 倍因子。
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
// build_combined_and_subproof_claims — 构造合并声明和子证明声明。
//
// 输入:
//   m_claims              — 每个多项式的 M 声明
//   g_hat_claims_per_poly — 每个多项式的 g_hat 声明列表
//   tau1                  — 合并参数
//
// 输出: pair<vector<F>, vector<F>>
//   .first  = combined_claims[i] = combine_claim(m_claims[i], g_hat_claims_per_poly[i], tau1)
//   .second = subproof_claims = 展平的 [m_claims, g_hat_claims...]
//             布局: [m_0, g_hat_0[0..mu], m_1, g_hat_1[0..mu], ...]
//
// subproof_claims 用于 blinding-side WHIR 的声明输入。
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
// construct_batched_eq_weights_from_gammas — 从 gamma 列表批量构造 beq 权重。
//
// 输入:
//   gammas                 — gamma 点列表
//   masking_challenge (rho)— 掩码挑战
//   tau2                   — 批量化参数
//   num_blinding_variables — ell
//
// 过程: 对每个 gamma_i, 计算 fill_eq_weights_at_gamma (完整版, ell+1 变量),
//       然后按 tau2^i 加权累积。
//
// 输出: Covector<F>, 长度 = 2^(ell+1)
//       = Σ_i tau2^i * beq((pow(gamma_i), -rho), .)
//
// 用于 blinding-side WHIR 的 beq 权重约束验证。
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
