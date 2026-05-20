#pragma once

// ============================================================================
// utilities.hpp — 代数工具函数
//
// 纯顺序实现，对应 WHIR Rust src/algebra/mod.rs
// （无 rayon 并行；大规模输入改用 OpenMP）。
//
//   geometric_sequence(base, n)         — (1, base, base^2, ..., base^{n-1})
//   mixed_dot / dot                     — 内积
//   tensor_product                      — 外积（Kronecker 积）
//   mixed_scalar_mul_add / scalar_mul_add — accumulator += weight * vec
//   mixed_univariate_evaluate / univariate_evaluate — Horner 求值
//   geometric_accumulate                — acc[i] += sum_j s_j * p_j^i
//   lift                                — 逐元素映射 Source -> Target
// ============================================================================

#include "embedding.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace whir::algebra {

// 返回 (1, base, base^2, ..., base^{length-1})。
template <typename F>
std::vector<F> geometric_sequence(const F& base, std::size_t length) {
    std::vector<F> out;
    out.reserve(length);
    F current = F::one();
    for (std::size_t i = 0; i < length; ++i) {
        out.push_back(current);
        current *= base;
    }
    return out;
}

// 混合域内积: sum_i emb.mixed_mul(a[i], b[i])。
template <typename M>
typename M::Target mixed_dot(
    const M& emb,
    std::span<const typename M::Target> a,
    std::span<const typename M::Source> b
) {
    using Tgt = typename M::Target;
    assert(a.size() == b.size());
    Tgt acc{};

#ifdef _OPENMP
    if (a.size() >= 4096) {
        const int threads = omp_get_max_threads();
        std::vector<Tgt> partial(static_cast<std::size_t>(threads), Tgt::zero());

        #pragma omp parallel
        {
            const int tid = omp_get_thread_num();
            Tgt local = Tgt::zero();

            #pragma omp for nowait
            for (std::ptrdiff_t pi = 0; pi < static_cast<std::ptrdiff_t>(a.size()); ++pi) {
                const std::size_t i = static_cast<std::size_t>(pi);
                local = local + emb.mixed_mul(a[i], b[i]);
            }

            partial[static_cast<std::size_t>(tid)] = local;
        }

        for (const auto& p : partial) acc = acc + p;
        return acc;
    }
#endif

    for (std::size_t i = 0; i < a.size(); ++i) {
        acc = acc + emb.mixed_mul(a[i], b[i]);
    }
    return acc;
}

// Identity 域内积: sum_i a[i] * b[i]。
template <typename F>
F dot(std::span<const F> a, std::span<const F> b) {
    Identity<F> id;
    return mixed_dot<Identity<F>>(id, a, b);
}

// 张量（Kronecker）积: out[i * |b| + j] = a[i] * b[j]。
template <typename F>
std::vector<F> tensor_product(std::span<const F> a, std::span<const F> b) {
    std::vector<F> out(a.size() * b.size());
#ifdef _OPENMP
    #pragma omp parallel for if(out.size() >= 4096)
#endif
    for (std::ptrdiff_t pi = 0; pi < static_cast<std::ptrdiff_t>(a.size()); ++pi) {
        const std::size_t i = static_cast<std::size_t>(pi);
        for (std::size_t j = 0; j < b.size(); ++j) {
            out[i * b.size() + j] = a[i] * b[j];
        }
    }
    return out;
}

// 逐元素提升: out[i] = emb.map(src[i])。
template <typename M>
std::vector<typename M::Target> lift(const M& emb, std::span<const typename M::Source> src) {
    std::vector<typename M::Target> out(src.size());
#ifdef _OPENMP
    #pragma omp parallel for if(src.size() >= 4096)
#endif
    for (std::ptrdiff_t pi = 0; pi < static_cast<std::ptrdiff_t>(src.size()); ++pi) {
        const std::size_t i = static_cast<std::size_t>(pi);
        out[i] = emb.map(src[i]);
    }
    return out;
}

// 混合域标量乘加: accumulator[i] += weight * vector[i]。
template <typename M>
void mixed_scalar_mul_add(
    const M& emb,
    std::span<typename M::Target> accumulator,
    typename M::Target weight,
    std::span<const typename M::Source> vector_
) {
    assert(accumulator.size() == vector_.size());
#ifdef _OPENMP
    #pragma omp parallel for if(vector_.size() >= 4096)
#endif
    for (std::ptrdiff_t pi = 0; pi < static_cast<std::ptrdiff_t>(vector_.size()); ++pi) {
        const std::size_t i = static_cast<std::size_t>(pi);
        accumulator[i] = accumulator[i] + emb.mixed_mul(weight, vector_[i]);
    }
}

// Identity 域标量乘加: accumulator[i] += weight * vector[i]。
template <typename F>
void scalar_mul_add(std::span<F> accumulator, F weight, std::span<const F> vector_) {
    Identity<F> id;
    mixed_scalar_mul_add<Identity<F>>(id, accumulator, weight, vector_);
}

// Horner 法求一元多项式值（混合域）:
//   P(x) = c_0 + c_1*x + ... + c_{n-1}*x^{n-1}
//        = c_0 + x*(c_1 + x*(c_2 + ... + x*c_{n-1}))
//
// 从最高次项向下扫描系数。
template <typename M>
typename M::Target mixed_univariate_evaluate(
    const M& emb,
    std::span<const typename M::Source> coefficients,
    typename M::Target point
) {
    using Tgt = typename M::Target;
    if (coefficients.empty()) return Tgt{};

    Tgt acc = emb.map(coefficients.back());
    for (std::size_t i = coefficients.size() - 1; i > 0; --i) {
        acc *= point;
        acc = emb.mixed_add(acc, coefficients[i - 1]);
    }
    return acc;
}

// Identity 域 Horner 求值。
template <typename F>
F univariate_evaluate(std::span<const F> coefficients, F point) {
    Identity<F> id;
    return mixed_univariate_evaluate<Identity<F>>(id, coefficients, point);
}

// 几何级数累加:
//   accumulator[i] += sum_j (scalars[j] * points[j]^i)
//
// 遍历 accumulator 的每个条目；对每个条目累加各标量，
// 然后将标量乘以对应的 point 以推进到下一次幂。
template <typename F>
void geometric_accumulate(
    std::span<F> accumulator,
    std::vector<F> scalars,
    std::span<const F> points
) {
    assert(scalars.size() == points.size());
#ifdef _OPENMP
    if (accumulator.size() >= 4096) {
        const std::size_t half = accumulator.size() / 2;
        std::vector<F> scalars_high(scalars.size());
        for (std::size_t j = 0; j < scalars.size(); ++j) {
            scalars_high[j] = scalars[j] * points[j].pow(static_cast<std::uint64_t>(half));
        }

        #pragma omp parallel sections
        {
            #pragma omp section
            {
                geometric_accumulate<F>(accumulator.subspan(0, half), std::move(scalars), points);
            }
            #pragma omp section
            {
                geometric_accumulate<F>(accumulator.subspan(half), std::move(scalars_high), points);
            }
        }
        return;
    }
#endif

    for (auto& entry : accumulator) {
        for (std::size_t j = 0; j < scalars.size(); ++j) {
            entry = entry + scalars[j];
            scalars[j] = scalars[j] * points[j];
        }
    }
}

} // namespace whir::algebra
