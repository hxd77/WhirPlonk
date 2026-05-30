#pragma once

// ============================================================================
// multilinear_point.hpp — 多线性扩张求值点
//
// 封装 F^n 中的点 (x_1, ..., x_n)，用于多线性求值。
// 提供 eq_poly() 计算相等多项式:
//   eq(c, p) = prod_i (c_i * p_i + (1 - c_i) * (1 - p_i))
//
// 这是 Lagrange 基在二进制点上的求值:
//   eq(c, p) = 1 当且仅当 c == p（作为二进制向量），否则为 0
//
// 对应 WHIR Rust: src/algebra/multilinear_point.rs
// ============================================================================

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace whir::algebra {

template <typename F>
class MultilinearPoint {
public:
    std::vector<F> coords;

    MultilinearPoint() = default;
    explicit MultilinearPoint(std::vector<F> c) : coords(std::move(c)) {}
    explicit MultilinearPoint(F value) : coords{value} {}

    // 变元数 n
    std::size_t num_variables() const noexcept { return coords.size(); }

    // 单个布尔点 p（大端比特编码）处的 eq(c, p):
    //   eq(c, p) = prod_i (c_i * p_i + (1 - c_i) * (1 - p_i))
    //
    // 逆序遍历 coords 以匹配大端比特序。
    F eq_poly(std::size_t point) const {
        const std::size_t n = coords.size();
        assert(n == 0 ? point == 0 : point < (std::size_t{1} << n));

        F acc = F::one();
        for (auto it = coords.rbegin(); it != coords.rend(); ++it) {
            const bool bit = (point & 1u) != 0;
            acc = acc * (bit ? *it : (F::one() - *it));
            point >>= 1;
        }
        return acc;
    }

    // 返回 [eq(c, 0), eq(c, 1), ..., eq(c, 2^n - 1)] — 布尔超立方上
    // 完整的 Lagrange 基向量。
    // 等价于 multilinear.hpp 中的 eval_eq。
    std::vector<F> eq_weights() const {
        std::vector<F> out;
        const std::size_t n = std::size_t{1} << coords.size();
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) out.push_back(eq_poly(i));
        return out;
    }
};

} // namespace whir::algebra
