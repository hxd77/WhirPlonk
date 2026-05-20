#pragma once

// ============================================================================
// multilinear.hpp — 多线性扩张求值与相等多项式
//
// 布尔超立方上多线性多项式的核心运算:
//
//   mixed_multilinear_extend<M>(emb, evals, point)
//       对由 evals（{0,1}^k 上的取值）定义的 MLE 在任意点处求值。
//       通过嵌入 M 支持混合域。
//
//   multilinear_extend<F>(evals, point)
//       Identity 域版本的简写。
//
//   eval_eq<F>(accumulator, point, scalar)
//       累加相等多项式: acc[b] += scalar * eq(point, b)。
//
// 对应 WHIR Rust: src/algebra/multilinear.rs
// point.size() ∈ {0,1,2,3,4} 时使用完全展开的插值，
// 与 Rust 中手工优化的递归深度和乘加顺序完全一致。
// ============================================================================

#include "embedding.hpp"

#include <cassert>
#include <cstddef>
#include <span>
#include <vector>

namespace whir::algebra {

// 对多线性扩张在 point 处求值。
//
// evals[k] = f(k)，k ∈ {0,1}^n（超立方取值）。
// 返回 f(point)，point ∈ F^n 为任意点。
//
// point.size() <= 4 时使用完全展开的插值，与 Rust 的递归深度
// 和运算顺序精确匹配。
// 更高维时回退到递归半分法:
//   f(point) = f(point[0]=0) + point[0] * (f(point[0]=1) - f(point[0]=0))
template <typename M>
typename M::Target mixed_multilinear_extend(
    const M& emb,
    std::span<const typename M::Source> evals,
    std::span<const typename M::Target> point
) {
    using Src = typename M::Source;
    using Tgt = typename M::Target;
    assert(evals.size() == (std::size_t{1} << point.size()));

    // 混合域线性插值: a + c * (b - a)
    auto mixed = [&](const Src& a, const Src& b, const Tgt& c) -> Tgt {
        return emb.mixed_add(emb.mixed_mul(c, b - a), a);
    };

    switch (point.size()) {
        case 0:
            return emb.map(evals[0]);
        case 1:
            return mixed(evals[0], evals[1], point[0]);
        case 2: {
            const Tgt a0 = mixed(evals[0], evals[1], point[1]);
            const Tgt a1 = mixed(evals[2], evals[3], point[1]);
            return a0 + (a1 - a0) * point[0];
        }
        case 3: {
            const Tgt a00 = mixed(evals[0], evals[1], point[2]);
            const Tgt a01 = mixed(evals[2], evals[3], point[2]);
            const Tgt a10 = mixed(evals[4], evals[5], point[2]);
            const Tgt a11 = mixed(evals[6], evals[7], point[2]);
            const Tgt a0  = a00 + (a01 - a00) * point[1];
            const Tgt a1  = a10 + (a11 - a10) * point[1];
            return a0 + (a1 - a0) * point[0];
        }
        case 4: {
            const Tgt a000 = mixed(evals[0],  evals[1],  point[3]);
            const Tgt a001 = mixed(evals[2],  evals[3],  point[3]);
            const Tgt a010 = mixed(evals[4],  evals[5],  point[3]);
            const Tgt a011 = mixed(evals[6],  evals[7],  point[3]);
            const Tgt a100 = mixed(evals[8],  evals[9],  point[3]);
            const Tgt a101 = mixed(evals[10], evals[11], point[3]);
            const Tgt a110 = mixed(evals[12], evals[13], point[3]);
            const Tgt a111 = mixed(evals[14], evals[15], point[3]);
            const Tgt a00 = a000 + (a001 - a000) * point[2];
            const Tgt a01 = a010 + (a011 - a010) * point[2];
            const Tgt a10 = a100 + (a101 - a100) * point[2];
            const Tgt a11 = a110 + (a111 - a110) * point[2];
            const Tgt a0  = a00 + (a01 - a00) * point[1];
            const Tgt a1  = a10 + (a11 - a10) * point[1];
            return a0 + (a1 - a0) * point[0];
        }
        default: {
            // 递归半分: 将 evals 拆为 x=0 和 x=1 两半。
            const std::size_t half = evals.size() / 2;
            const Tgt f0 = mixed_multilinear_extend<M>(
                emb, evals.subspan(0, half), point.subspan(1));
            const Tgt f1 = mixed_multilinear_extend<M>(
                emb, evals.subspan(half), point.subspan(1));
            return f0 + (f1 - f0) * point[0];
        }
    }
}

// Identity 域的 multilinear_extend 简写。
template <typename F>
F multilinear_extend(std::span<const F> evals, std::span<const F> point) {
    Identity<F> id;
    return mixed_multilinear_extend<Identity<F>>(id, evals, point);
}

// 在布尔超立方上累加相等多项式:
//   accumulator[b] += scalar * eq(point, b)
//
// 其中 b 遍历 {0,1}^n，
//   eq(point, b) = prod_i (point[i] * b_i + (1 - point[i]) * (1 - b_i))
//
// 递归半分法: 对 point[0] = x0，
//   s0 = scalar * (1 - x0)，s1 = scalar * x0
// 然后对 accumulator 的两半递归。
template <typename F>
void eval_eq(std::span<F> accumulator, std::span<const F> point, F scalar) {
    assert(accumulator.size() == (std::size_t{1} << point.size()));
    if (point.empty()) {
        accumulator[0] += scalar;
        return;
    }
    const F x0 = point[0];
    const F s1 = scalar * x0;
    const F s0 = scalar - s1;
    const std::size_t half = accumulator.size() / 2;
    eval_eq<F>(accumulator.subspan(0, half), point.subspan(1), s0);
    eval_eq<F>(accumulator.subspan(half),    point.subspan(1), s1);
}

} // namespace whir::algebra
