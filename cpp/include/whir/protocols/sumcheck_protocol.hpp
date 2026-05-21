#pragma once

// ============================================================================
// sumcheck_protocol.hpp — Fiat-Shamir sumcheck 协议
//
// 将底层 sumcheck 代数（algebra/sumcheck.hpp）与 Fiat-Shamir transcript
// 交互封装为完整的 sumcheck 轮次。
//
// 协议流程（每轮）:
//   证明者                               验证者
//   (c0, c2) = compute_polynomial(a, b)
//   c1 = sum - 2*c0 - c2
//   ---- 发送 c0, c2 ----->              读取 c0, c2；c1 = sum - 2*c0 - c2
//   执行 PoW（若有）                     验证 PoW（若有）
//   <---- 发送 r ---------               挤压挑战 r
//   fold(a, r); fold(b, r)               sum = (c2*r + c1)*r + c0
//   sum = (c2*r + c1)*r + c0
//
// 初始大小 = 2^n；每轮将向量长度减半。
// 经过 num_rounds 轮后: final_size = 2^(n - num_rounds)。
//
// 配置参数:
//   initial_size — 初始向量长度（必须是 2 的幂次）
//   num_rounds   — 折叠轮次数
//   round_pow    — 每轮 PoW 配置（零难度 = 跳过）
//
// C++ 代数: algebra/sumcheck.hpp (compute_sumcheck_polynomial / fold)
// 对应 Rust 文件: src/protocols/sumcheck.rs
// ============================================================================

#include "../algebra/sumcheck.hpp"
#include "../algebra/multilinear_point.hpp"
#include "../hash/blake3_engine.hpp"
#include "../hash/sha2_engine.hpp"
#include "../protocols/proof_of_work.hpp"
#include "../transcript/transcript.hpp"
#include "../profiling.hpp"

#include <cassert>
#include <cmath>
#include <vector>

namespace whir::protocols::sumcheck {

template <typename F>
struct Config {
    std::size_t initial_size;                         // 初始多项式大小（2 的幂次）
    ::whir::protocols::pow::PowConfig round_pow;      // 每轮 PoW（零难度 = 跳过）
    std::size_t num_rounds;                           // 折叠轮次数

    /// 验证配置: initial_size 是 2 的幂次且 >= 2^num_rounds。
    bool validate() const {
        if ((initial_size & (initial_size - 1)) != 0) return false;
        std::size_t min_size = std::size_t{1} << num_rounds;
        if (initial_size < min_size) return false;
        return true;
    }

    /// 所有轮次后的向量长度: 2^(n - num_rounds)。
    std::size_t final_size() const {
        return initial_size >> num_rounds;
    }

    // =========================================================================
    // prove — 执行 sumcheck 证明者
    //
    // @param a    第一个多线性多项式（就地折叠修改）
    // @param b    第二个多线性多项式（就地折叠修改）
    // @param sum  声明的内积（每轮就地更新）
    // @return     折叠随机性 MultilinearPoint(r_0, ..., r_{t-1})
    //
    // 每轮算法:
    //   1. compute_sumcheck_polynomial(a, b) -> (c0, c2)
    //   2. 推导 c1 = sum - c0.double() - c2
    //   3. 向 transcript 发送 c0, c2
    //   4. 执行 PoW（若已配置）
    //   5. 从 transcript 挤压随机域元素 r
    //   6. fold(a, r); fold(b, r) — 向量长度减半
    //   7. sum = (c2*r + c1)*r + c0 — 更新声明值
    // =========================================================================
    template <typename Transcript>
    ::whir::algebra::MultilinearPoint<F> prove(
        Transcript& prover_state,
        std::vector<F>& a,
        std::vector<F>& b,
        F& sum) const
    {
        assert(validate());
        assert(a.size() == initial_size);
        assert(b.size() == initial_size);

        std::vector<F> folding_randomness;
        folding_randomness.reserve(num_rounds);

        ::whir::hash::Blake3 blake3_pow_engine;
        ::whir::hash::Sha2 sha2_pow_engine;
        auto pow_engine_lookup =
            [&blake3_pow_engine, &sha2_pow_engine](::whir::EngineId id)
                -> const ::whir::hash::HashEngine& {
            if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_pow_engine;
            return blake3_pow_engine;
        };

        for (std::size_t r = 0; r < num_rounds; ++r) {
            // 计算二次 sumcheck 多项式系数
            F c0{};
            F c2{};
            {
                ::whir::profile::ScopedTimer timer("prover", a.size(), "sumcheck_compute");
                auto coeffs = ::whir::algebra::compute_sumcheck_polynomial<F>(a, b);
                c0 = coeffs.first;
                c2 = coeffs.second;
            }
            // c0 = sum of a[2i]*b[2i], c2 = sum of a[2i+1]*b[2i+1]
            // c1 为推导值: 验证者从 (sum, c0, c2) 重新计算
            F c1 = sum - (c0 + c0) - c2;

            // 发送 c0, c2（c1 隐含）
            prover_state.prover_message(c0);
            prover_state.prover_message(c2);

            // 执行 PoW（难度为 0 时为空操作）
            round_pow.prove(prover_state, pow_engine_lookup);

            // 挤压折叠随机性 r
            F rnd = prover_state.template verifier_message<F>();
            folding_randomness.push_back(rnd);

            // 折叠向量: v'[i] = v[2i] + r * (v[2i+1] - v[2i])
            {
                ::whir::profile::ScopedTimer timer("prover", a.size(), "sumcheck_fold_a");
                ::whir::algebra::fold<F>(a, rnd);
            }
            {
                ::whir::profile::ScopedTimer timer("prover", b.size(), "sumcheck_fold_b");
                ::whir::algebra::fold<F>(b, rnd);
            }

            // 更新声明的和: sum' = c0 + c1*r + c2*r^2
            sum = (c2 * rnd + c1) * rnd + c0;
        }

        return ::whir::algebra::MultilinearPoint<F>{std::move(folding_randomness)};
    }

    // =========================================================================
    // verify — 执行 sumcheck 验证者
    //
    // 从 transcript 读取 c0, c2，验证 PoW，挤压折叠随机性，
    // 并更新声明的和。作为 prove() 的确定性对应 —
    // 挤压相同的 transcript 值。
    // =========================================================================
    template <typename Transcript>
    ::whir::algebra::MultilinearPoint<F> verify(
        Transcript& verifier_state,
        F& sum) const
    {
        assert(validate());

        std::vector<F> folding_randomness;
        folding_randomness.reserve(num_rounds);

        ::whir::hash::Blake3 blake3_pow_engine;
        ::whir::hash::Sha2 sha2_pow_engine;
        auto pow_engine_lookup =
            [&blake3_pow_engine, &sha2_pow_engine](::whir::EngineId id)
                -> const ::whir::hash::HashEngine& {
            if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_pow_engine;
            return blake3_pow_engine;
        };

        for (std::size_t r = 0; r < num_rounds; ++r) {
            // 从 transcript 读取 c0, c2
            F c0, c2;
            if (!verifier_state.prover_message(c0)) return {};
            if (!verifier_state.prover_message(c2)) return {};
            // 推导 c1 使得 sum = c0 + c1*r + c2*r^2 在检查点成立
            F c1 = sum - (c0 + c0) - c2;

            // 验证 PoW
            if (!round_pow.verify(verifier_state, pow_engine_lookup)) return {};

            // 挤压与证明者相同的折叠随机性
            F rnd = verifier_state.template verifier_message<F>();
            folding_randomness.push_back(rnd);

            // 更新声明的和: sum' = c0 + c1*r + c2*r^2
            sum = (c2 * rnd + c1) * rnd + c0;
        }

        return ::whir::algebra::MultilinearPoint<F>{std::move(folding_randomness)};
    }
};

} // namespace whir::protocols::sumcheck
