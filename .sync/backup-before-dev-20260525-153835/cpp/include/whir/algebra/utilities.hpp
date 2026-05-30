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

#include <algorithm>
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

template <typename F>
F geometric_mul_step(const F& value, const F& point) noexcept {
    return value * point;
}

inline GoldilocksExt2 geometric_mul_step(const GoldilocksExt2& value, const GoldilocksExt2& point) noexcept {
    if (point.c1().is_zero()) {
        const Goldilocks scalar = point.c0();
        return {value.c0() * scalar, value.c1() * scalar};
    }
    return value * point;
}

inline GoldilocksExt3 geometric_mul_step(const GoldilocksExt3& value, const GoldilocksExt3& point) noexcept {
    if (point.c1().is_zero() && point.c2().is_zero()) {
        const Goldilocks scalar = point.c0();
        return {value.c0() * scalar, value.c1() * scalar, value.c2() * scalar};
    }
    return value * point;
}

template <typename F>
F geometric_pow_step(const F& point, std::uint64_t exp) noexcept {
    return point.pow(exp);
}

inline GoldilocksExt2 geometric_pow_step(const GoldilocksExt2& point, std::uint64_t exp) noexcept {
    if (point.c1().is_zero()) {
        return GoldilocksExt2::from_base(point.c0().pow(exp));
    }
    return point.pow(exp);
}

inline GoldilocksExt3 geometric_pow_step(const GoldilocksExt3& point, std::uint64_t exp) noexcept {
    if (point.c1().is_zero() && point.c2().is_zero()) {
        return GoldilocksExt3::from_base(point.c0().pow(exp));
    }
    return point.pow(exp);
}

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

#ifdef _OPENMP
    const int threads = omp_get_max_threads();
    if (threads > 1 && coefficients.size() >= 4096) {
        constexpr std::size_t min_chunk = 1024;
        const std::size_t target_chunks = static_cast<std::size_t>(threads) * 4;
        const std::size_t chunk_size =
            std::max<std::size_t>(min_chunk, (coefficients.size() + target_chunks - 1) / target_chunks);
        const std::size_t chunks = (coefficients.size() + chunk_size - 1) / chunk_size;
        std::vector<Tgt> partials(chunks, Tgt{});

        #pragma omp parallel for schedule(static)
        for (std::ptrdiff_t ci = 0; ci < static_cast<std::ptrdiff_t>(chunks); ++ci) {
            const std::size_t chunk = static_cast<std::size_t>(ci);
            const std::size_t start = chunk * chunk_size;
            const std::size_t end = std::min(coefficients.size(), start + chunk_size);
            if (start >= end) continue;

            Tgt local = emb.map(coefficients[end - 1]);
            for (std::size_t i = end - 1; i > start; --i) {
                local *= point;
                local = emb.mixed_add(local, coefficients[i - 1]);
            }
            if (start != 0) {
                local *= point.pow(static_cast<std::uint64_t>(start));
            }
            partials[chunk] = local;
        }

        Tgt acc{};
        for (const auto& part : partials) {
            acc += part;
        }
        return acc;
    }
#endif

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
    const int threads = omp_get_max_threads();
    if (threads > 1 && accumulator.size() >= 4096 && !points.empty()) {
        constexpr std::size_t min_chunk = 1024;
        const std::size_t target_chunks = static_cast<std::size_t>(threads) * 4;
        const std::size_t chunk_size =
            std::max<std::size_t>(min_chunk, (accumulator.size() + target_chunks - 1) / target_chunks);
        const std::size_t chunks = (accumulator.size() + chunk_size - 1) / chunk_size;

        #pragma omp parallel for schedule(static)
        for (std::ptrdiff_t ci = 0; ci < static_cast<std::ptrdiff_t>(chunks); ++ci) {
            const std::size_t start = static_cast<std::size_t>(ci) * chunk_size;
            const std::size_t end = std::min(accumulator.size(), start + chunk_size);

            // 每个块独立推进几何级数到 start，之后保持与串行路径相同的逐项求和顺序。
            std::vector<F> local_scalars = scalars;
            for (std::size_t j = 0; j < local_scalars.size(); ++j) {
                local_scalars[j] =
                    local_scalars[j] * geometric_pow_step(points[j], static_cast<std::uint64_t>(start));
            }

            for (std::size_t i = start; i < end; ++i) {
                F entry = accumulator[i];
                for (std::size_t j = 0; j < local_scalars.size(); ++j) {
                    entry = entry + local_scalars[j];
                    local_scalars[j] = geometric_mul_step(local_scalars[j], points[j]);
                }
                accumulator[i] = entry;
            }
        }
        return;
    }
#endif

    for (auto& entry : accumulator) {
        for (std::size_t j = 0; j < scalars.size(); ++j) {
            entry = entry + scalars[j];
            scalars[j] = geometric_mul_step(scalars[j], points[j]);
        }
    }
}

} // namespace whir::algebra
