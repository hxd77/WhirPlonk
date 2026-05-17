#pragma once

// ===========================================================================
// sumcheck_protocol.hpp — 协议层 sumcheck 包装
// 对应 WHIR 中的 src/protocols/sumcheck.rs。
//
// 在 algebra/sumcheck.hpp 的低层纯函数之上, 加上 Fiat-Shamir transcript 交互,
// 构成完整的 sumcheck 协议轮次。
//
// 协议流程 (每轮):
//   Prover                               Verifier
//   (c0, c2) = compute_polynomial(a, b)
//   c1 = sum - 2c0 - c2
//   ---- send c0, c2 ----->              read c0, c2; c1 = sum - 2c0 - c2
//   do PoW (if any)                      verify PoW (if any)
//   <---- send r ---------               squeeze challenge r
//   fold(a, r); fold(b, r)               sum = (c2*r + c1)*r + c0
//   sum = (c2*r + c1)*r + c0
//
// 初始 size = 2^n, 每轮减半, num_rounds 轮后 final_size = 2^(n-rounds)。
//
// Config 参数:
//   initial_size — 初始向量长度 (必须是 2 的幂)
//   num_rounds   — 折叠轮数
//   round_pow    — 每轮的 PoW 配置 (零难度 = 跳过)
//
// 对应 C++ algebra: algebra/sumcheck.hpp (compute_sumcheck_polynomial / fold)
// ===========================================================================

#include "../algebra/sumcheck.hpp"
#include "../algebra/multilinear_point.hpp"
#include "../hash/blake3_engine.hpp"
#include "../hash/sha2_engine.hpp"
#include "../protocols/proof_of_work.hpp"
#include "../transcript/transcript.hpp"

#include <cassert>
#include <cmath>
#include <vector>

namespace whir::protocols::sumcheck {

template <typename F>
struct Config {
    std::size_t initial_size;      // 初始多项式大小 (2 的幂)
    ::whir::protocols::pow::PowConfig round_pow;  // 每轮 PoW (zero-diff = skip)
    std::size_t num_rounds;        // 折叠轮数

    /// 验证配置合法性: initial_size 是 2 的幂, 且 ≥ 2^num_rounds
    bool validate() const {
        if ((initial_size & (initial_size - 1)) != 0) return false; //initial_size是2的幂
        std::size_t min_size = std::size_t{1} << num_rounds; //min_size=2^num_rounds
        if (initial_size < min_size) return false; //如果初始大小<min_size,说明不够折叠
        return true;
    }

    /// 折叠后的最终大小 = 2^(n - num_rounds)
    std::size_t final_size() const {
        return initial_size >> num_rounds;
    }

    // =========================================================================
    // prove — 执行 sumcheck 证明
    //
    // a, b, sum 会被原地修改。返回每轮的折叠随机性 MultilinearPoint(r_0, ..., r_{t-1})。
    //
    // 算法 (每轮):
    //   1. compute_sumcheck_polynomial(a, b) → (c0, c2)
    //   2. 推导 c1 = sum - c0.double() - c2
    //   3. 发送 c0, c2 到 transcript
    //   4. 执行 PoW (如果配置了)
    //   5. 从 transcript 挤出一个随机域元素 r
    //   6. fold(a, r); fold(b, r) — 把向量长度减半
    //   7. sum = (c2*r + c1)*r + c0 — 更新声称值
    // =========================================================================
    template <typename Transcript>
    ::whir::algebra::MultilinearPoint<F> prove(
        Transcript& prover_state,
        std::vector<F>& a,      // 第一个多项式 (原地折叠)
        std::vector<F>& b,      // 第二个多项式 (原地折叠)
        F& sum) const           // 声称的内积值 (原地更新)
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
            // 1. 计算 sumcheck 多项式系数
            auto [c0, c2] = ::whir::algebra::compute_sumcheck_polynomial<F>(a, b);
            // c0 = Σ a[2i]*b[2i+1], c2 = Σ a[2i+1]*b[2i]
            // c1 = Σ a[i]*b[i] - 2*c0 - c2 = sum - c0 - c0 - c2
            F c1 = sum - (c0 + c0) - c2;

            // 2. 发送 c0, c2 (c1 由 verifier 自行推导)
            prover_state.prover_message(c0);
            prover_state.prover_message(c2);

            // 3. 执行 PoW (如果难度 > 0, 需要提供 engine)
            //把nonce写入transcript中
            round_pow.prove(prover_state, pow_engine_lookup);

            // 4. 接收折叠随机性 r
            F rnd = prover_state.template verifier_message<F>();
            folding_randomness.push_back(rnd);

            // 5. 折叠向量: v'[i] = v[2i] + rnd * (v[2i+1] - v[2i])
            //low[i] += (high[i] - low[i]) * weight,
            ::whir::algebra::fold<F>(a, rnd);
            ::whir::algebra::fold<F>(b, rnd);

            // 6. 更新声称值: sum' = c0 + c1*rnd + c2*rnd²
            sum = (c2 * rnd + c1) * rnd + c0;
        }

        return ::whir::algebra::MultilinearPoint<F>{std::move(folding_randomness)};
    }

    // =========================================================================
    // verify — 执行 sumcheck 验证
    //
    // 从 transcript 读取 c0, c2, 验证 PoW, 挤出折叠随机性, 更新 sum。
    // 与 prove 的 deterministic 对应 — 挤出相同的随机值。
    // =========================================================================
    template <typename Transcript>
    ::whir::algebra::MultilinearPoint<F> verify(
        Transcript& verifier_state,
        F& sum) const           // 声称的内积值 (原地更新)
    {
        assert(validate());

        std::vector<F> folding_randomness;
        folding_randomness.reserve(num_rounds); //num_rounds大小

        ::whir::hash::Blake3 blake3_pow_engine;
        ::whir::hash::Sha2 sha2_pow_engine;
        auto pow_engine_lookup =
            [&blake3_pow_engine, &sha2_pow_engine](::whir::EngineId id)
                -> const ::whir::hash::HashEngine& {
            if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_pow_engine;
            return blake3_pow_engine;
        };

        for (std::size_t r = 0; r < num_rounds; ++r) {
            // 1. 读取 c0, c2
            F c0, c2;
            if (!verifier_state.prover_message(c0)) return {};
            if (!verifier_state.prover_message(c2)) return {};
            F c1 = sum - (c0 + c0) - c2; //算出c1

            // 2. 验证 PoW ,拿nonce验证生成的hash转换为数字后是否小于阈值
            if (!round_pow.verify(verifier_state, pow_engine_lookup)) return {};

            // 3. 挤出折叠随机性 (和 prover 相同的确定性值)
            F rnd = verifier_state.template verifier_message<F>();
            folding_randomness.push_back(rnd);

            // 4. 更新声称值
            sum = (c2 * rnd + c1) * rnd + c0;
        }

        return ::whir::algebra::MultilinearPoint<F>{std::move(folding_randomness)};
    }
};

} // namespace whir::protocols::sumcheck
