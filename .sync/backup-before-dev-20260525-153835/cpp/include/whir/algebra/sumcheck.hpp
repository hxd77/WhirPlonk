#pragma once

// ============================================================================
// sumcheck.hpp — Sumcheck 协议原语
//
// WHIR 折叠方案中 sumcheck 轮次的核心例程:
//
//   compute_sumcheck_polynomial(a, b)
//       给定 A(X) = a0 + X*(a1 - a0) 和 B(X) = b0 + X*(b1 - b0)，
//       返回 (P(0), X^2 系数)，其中 P(X) = sum_i A_i(X) * B_i(X)。
//
//   fold(values, weight)
//       原地线性插值: v[i] = v[i] + weight * (v[i+half] - v[i])，
//       然后截断至半长。用于验证者发送挑战后折叠多项式求值。
//
//   mixed_eval<M>(emb, coeff, eval, scalar)
//       对以 {0,1}^k 上系数给出的多线性多项式在任意点处求值，
//       支持混合域。
//
// 对应 WHIR Rust: src/algebra/sumcheck.rs
// 仅顺序实现；大规模输入使用 OpenMP 并行。
// ============================================================================

#include "embedding.hpp"

#include <cassert>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace whir::algebra {

// 计算 sumcheck 多项式的 (P(0), X^2 系数):
//   P(X) = sum_i [(a0_i + X*(a1_i - a0_i)) * (b0_i + X*(b1_i - b0_i))]
//        = acc0 + C_1*X + acc2*X^2
//
// 仅需 acc0 和 acc2；C_1 由 (sum - acc0 - acc2) 恢复。
template <typename F>
std::pair<F, F> compute_sumcheck_polynomial(
    std::span<const F> a,
    std::span<const F> b
) {
    assert(a.size() == b.size());
    const std::size_t half = a.size() / 2;

    auto a0 = a.subspan(0, half);
    auto a1 = a.subspan(half);
    auto b0 = b.subspan(0, half);
    auto b1 = b.subspan(half);
    assert(a0.size() == a1.size());
    assert(b0.size() == b1.size());
    assert(a0.size() == b0.size());

    F acc0{};
    F acc2{};

#ifdef _OPENMP
    if (a0.size() >= 4096) {
        const int threads = omp_get_max_threads();
        std::vector<F> partial0(static_cast<std::size_t>(threads), F::zero());
        std::vector<F> partial2(static_cast<std::size_t>(threads), F::zero());

        #pragma omp parallel
        {
            const int tid = omp_get_thread_num();
            F local0 = F::zero();
            F local2 = F::zero();

            #pragma omp for nowait
            for (std::ptrdiff_t pi = 0; pi < static_cast<std::ptrdiff_t>(a0.size()); ++pi) {
                const std::size_t i = static_cast<std::size_t>(pi);
                local0 += a0[i] * b0[i];
                local2 += (a1[i] - a0[i]) * (b1[i] - b0[i]);
            }

            partial0[static_cast<std::size_t>(tid)] = local0;
            partial2[static_cast<std::size_t>(tid)] = local2;
        }

        for (std::size_t i = 0; i < partial0.size(); ++i) {
            acc0 += partial0[i];
            acc2 += partial2[i];
        }
        return {acc0, acc2};
    }
#endif

    for (std::size_t i = 0; i < a0.size(); ++i) {
        acc0 += a0[i] * b0[i];
        acc2 += (a1[i] - a0[i]) * (b1[i] - b0[i]);
    }
    return {acc0, acc2};
}

// 原地折叠: 在 weight 处线性插值并将数组减半。
//   values[i] = values[i] + weight * (values[i+half] - values[i])
// 然后截断至半长。
template <typename F>
void fold(std::vector<F>& values, F weight) {
    assert(values.size() % 2 == 0);
    const std::size_t half = values.size() / 2;
#ifdef _OPENMP
    #pragma omp parallel for if(half >= 4096)
#endif
    for (std::ptrdiff_t si = 0; si < static_cast<std::ptrdiff_t>(half); ++si) {
        const std::size_t i = static_cast<std::size_t>(si);
        values[i] = values[i] + (values[half + i] - values[i]) * weight;
    }
    values.resize(half);
    values.shrink_to_fit();
}

// 对多线性多项式在任意点处求值:
//   f(x) = sum_{b in {0,1}^n} coeff[b] * eq(b, x)
//
// coeff 属于 Source 域，eval/point 属于 Target 域。
// 递归半分法遍历各变元，标量贯穿传递:
//   f(x) = low(x_tail) + x_0 * high(x_tail)
// 其中 low/high 是 coeff 的两半。
template <typename M>
typename M::Target mixed_eval(
    const M& emb,
    std::span<const typename M::Source> coeff,
    std::span<const typename M::Target> eval,
    typename M::Target scalar
) {
    using Tgt = typename M::Target;
    assert(coeff.size() == (std::size_t{1} << eval.size()));

    if (eval.empty()) {
        return emb.mixed_mul(scalar, coeff[0]);
    }

    const Tgt x = eval[0];
    const auto tail = eval.subspan(1);
    const std::size_t half = coeff.size() / 2;
    const auto low  = coeff.subspan(0, half);
    const auto high = coeff.subspan(half);

    // 低半部分: 标量不变
    const Tgt a = mixed_eval<M>(emb, low,  tail, scalar);
    // 高半部分: 标量乘以当前变元
    const Tgt b = mixed_eval<M>(emb, high, tail, scalar * x);

    return a + b;
}

} // namespace whir::algebra
