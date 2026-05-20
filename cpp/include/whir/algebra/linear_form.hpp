#pragma once

// ============================================================================
// linear_form.hpp — 域上的抽象线性形式
//
// LinearForm<F> 表示布尔超立方 {0,1}^n 上的线性泛函。具体子类:
//
//   Covector<F>             — 显式系数向量，f(v) = <w, v>
//   MultilinearExtension<F> — 固定点 p 处的 MLE: f(v) = eq(p, v)
//   UnivariateEvaluation<F> — 一元多项式 f(v) = sum_i v_i * x^i
//
// 对应 WHIR Rust: src/algebra/linear_form/*.rs
// Rust 中为 trait；此处使用带虚函数分派的抽象基类。
// evaluate<M> 模板方法为各子类特有（非虚），因为嵌入类型参数
// 无法虚化。
// ============================================================================

#include "embedding.hpp"
#include "multilinear.hpp"
#include "utilities.hpp"

#include <cassert>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

namespace whir::algebra {

template <typename F>
class LinearForm {
public:
    virtual ~LinearForm() = default;

    // 返回线性形式定义域的维度（即 2^n）
    virtual std::size_t size() const = 0;

    // 在给定点上计算多线性扩张求值
    virtual F mle_evaluate(std::span<const F> point) const = 0;

    // 将 scalar * self 累加到 accumulator 上
    virtual void accumulate(std::span<F> accumulator, F scalar) const = 0;
};

// ============================================================================
// Covector — 显式权向量表示的线性泛函
//
// f(v_0, ..., v_{n-1}) = w_0 * v_0 + ... + w_{n-1} * v_{n-1}
//
// 权向量存储于 vector；mle_evaluate 计算 w 在给定点上的多线性扩张；
// accumulate 将 scalar * w 累加到 accumulator。
// ============================================================================
template <typename F>
class Covector final : public LinearForm<F> {
public:
    std::vector<F> vector;

    Covector() = default;
    explicit Covector(std::vector<F> v) : vector(std::move(v)) {}

    // 将任意 LinearForm 物化为显式系数向量，
    // 沿每个标准基方向累加。
    static Covector from_linear_form(const LinearForm<F>& lf) {
        std::vector<F> v(lf.size(), F{});
        lf.accumulate(v, F::one());
        return Covector{std::move(v)};
    }

    std::size_t size() const override { return vector.size(); }

    F mle_evaluate(std::span<const F> point) const override {
        return multilinear_extend<F>(std::span<const F>{vector}, point);
    }

    // accumulator += scalar * vector
    void accumulate(std::span<F> accumulator, F scalar) const override {
        scalar_mul_add<F>(accumulator, scalar, std::span<const F>{vector});
    }

    // 在嵌入 M 下求值: 返回 <w, M(v)>。
    template <typename M>
    typename M::Target evaluate(
        const M& emb,
        std::span<const typename M::Source> vec
    ) const {
        static_assert(std::is_same_v<F, typename M::Target>,
            "Covector::evaluate: M::Target must equal this Covector's F");
        assert(vector.size() == vec.size());
        return mixed_dot<M>(emb, std::span<const F>{vector}, vec);
    }
};

// ============================================================================
// MultilinearExtension — 固定点处的 MLE 求值
//
// 给定点 p = (p_0, ..., p_{n-1})，相等多项式为:
//   eq(p, x) = prod_i (p_i * x_i + (1 - p_i) * (1 - x_i))
//
// 当且仅当 x == p（作为布尔超立方上的点）时为 1，否则为 0。
// ============================================================================
template <typename F>
class MultilinearExtension final : public LinearForm<F> {
public:
    std::vector<F> point;

    MultilinearExtension() = default;
    explicit MultilinearExtension(std::vector<F> p) : point(std::move(p)) {}

    std::size_t size() const override { return std::size_t{1} << point.size(); }

    // eq(self.point, pt) = prod_i (l_i * r_i + (1 - l_i) * (1 - r_i))
    F mle_evaluate(std::span<const F> pt) const override {
        assert(point.size() == pt.size());
        F acc = F::one();
        for (std::size_t i = 0; i < point.size(); ++i) {
            const F l = point[i];
            const F r = pt[i];
            acc = acc * (l * r + (F::one() - l) * (F::one() - r));
        }
        return acc;
    }

    // 用 eq(point, *) 填充 accumulator 上所有布尔输入的值，
    // 并乘以 scalar: accumulator[b] += scalar * eq(point, b)。
    void accumulate(std::span<F> accumulator, F scalar) const override {
        eval_eq<F>(accumulator, std::span<const F>{point}, scalar);
    }

    // 在嵌入 M 下，对 vec 在 self.point 处进行 MLE 求值。
    template <typename M>
    typename M::Target evaluate(
        const M& emb,
        std::span<const typename M::Source> vec
    ) const {
        static_assert(std::is_same_v<F, typename M::Target>,
            "MultilinearExtension::evaluate: M::Target must equal this MLE's F");
        return mixed_multilinear_extend<M>(emb, vec, std::span<const F>{point});
    }
};

// ============================================================================
// UnivariateEvaluation — 通过 MLE 进行一元多项式求值
//
// 表示向量 (1, x, x^2, ..., x^{n-1}) 映射到多线性域。
// mle_evaluate 计算张量积:
//   prod_i ((1 - r_i) + r_i * x^{2^i})
// 当 r 被解释为二进制数时，等价于 sum_k r_k * x^k。
// ============================================================================
template <typename F>
class UnivariateEvaluation final : public LinearForm<F> {
public:
    std::size_t size_value; // 命名为 size_value 以避免与 size() 冲突
    F point;

    UnivariateEvaluation() : size_value(0), point{} {}
    UnivariateEvaluation(F x, std::size_t s) : size_value(s), point(x) {}

    std::size_t size() const override { return size_value; }

    // 张量积求值:
    //   result = prod_i ((1 - r_i) + r_i * x^{2^i})
    // 逆序遍历 pt，使 x^{2^i} 每步自乘。
    F mle_evaluate(std::span<const F> pt) const override {
        F x2i = point;
        F result = F::one();
        for (auto it = pt.rbegin(); it != pt.rend(); ++it) {
            const F r = *it;
            result *= (F::one() - r) + r * x2i;
            x2i = x2i * x2i;
        }
        return result;
    }

    // accumulator[i] += scalar * point^i
    void accumulate(std::span<F> accumulator, F scalar) const override {
        assert(accumulator.size() == size_value);
        F power = scalar;
        for (auto& entry : accumulator) {
            entry = entry + power;
            power = power * point;
        }
    }

    // 批量累加: accumulator += sum_j scalars[j] * (1, points[j], ...)。
    // 委托给 geometric_accumulate 以提高效率。
    static void accumulate_many(
        const std::vector<UnivariateEvaluation>& evaluators,
        std::span<F> accumulator,
        std::span<const F> scalars
    ) {
        assert(evaluators.size() == scalars.size());
        if (evaluators.empty()) return;

        const std::size_t size_check = evaluators.front().size_value;
        assert(accumulator.size() == size_check);
        for (const auto& e : evaluators) {
            assert(e.size_value == size_check);
        }

        std::vector<F> points;
        points.reserve(evaluators.size());
        for (const auto& e : evaluators) points.push_back(e.point);

        std::vector<F> scalars_vec(scalars.begin(), scalars.end());
        geometric_accumulate<F>(accumulator, std::move(scalars_vec), std::span<const F>{points});
    }

    // 在嵌入 M 下求值: sum_i vec[i] * point^i。
    template <typename M>
    typename M::Target evaluate(
        const M& emb,
        std::span<const typename M::Source> vec
    ) const {
        static_assert(std::is_same_v<F, typename M::Target>,
            "UnivariateEvaluation::evaluate: M::Target must equal this object's F");
        return mixed_univariate_evaluate<M>(emb, vec, point);
    }
};

} // namespace whir::algebra
