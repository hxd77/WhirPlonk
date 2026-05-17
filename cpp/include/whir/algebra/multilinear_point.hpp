#pragma once

// 对应 WHIR 中的 src/algebra/multilinear_point.rs。
// MultilinearPoint<F> 封装域 F 中的向量 (x_1, ..., x_n), 暴露:
//   num_variables()   —— 向量长度 n
//   eq_poly(point)    —— 相等多项式 eq(c, p) 在二进制点 p 上的取值
//   eq_weights()      —— 对布尔超立方上所有 2^n 个点的 eq_poly 值
// 与 Rust 侧的 eq_poly/eq_weights 输出逐位一致。

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace whir::algebra {

template <typename F>
class MultilinearPoint {
public:
    //coords是一个多维坐标点
    std::vector<F> coords; //和 Rust 的 pub Vec<F> 对齐, 外部可以直接读写。

    MultilinearPoint() = default;
    explicit MultilinearPoint(std::vector<F> c) : coords(std::move(c)) {} //explicit防止隐式类型转换 move表示把拥有c的内存控制权抢过来
    explicit MultilinearPoint(F value) : coords{value} {}

    //变量个数 n
    std::size_t num_variables() const noexcept { return coords.size(); }

    //eq(c, p) 在二进制点 p 上的取值, p 按大端解释:
    //   eq(c, p) = prod_i (c_i * p_i + (1 - c_i) * (1 - p_i))
    //当 c == p 时为 1, 否则为 0。
    //计算单个布尔点的拉格朗日基
    F eq_poly(std::size_t point) const {
        const std::size_t n = coords.size();
        assert(n == 0 ? point == 0 : point < (std::size_t{1} << n));

        F acc = F::one();
        //rbegin和rend反向遍历坐标数组(大端序映射)
        for (auto it = coords.rbegin(); it != coords.rend(); ++it) {
            //point&1u取出整数的最末位(0或1) 
            const bool bit = (point & 1u) != 0;

            //如果bit是1，取当前坐标值*it,如果是bit=0,取1-*it
            acc = acc * (bit ? *it : (F::one() - *it));
            //向右移动，循环处理下一位
            point >>= 1;
        }
        return acc;
    }

    //对布尔超立方上所有点求 eq_poly, 得到长度 2^n 的向量。
    std::vector<F> eq_weights() const {
        std::vector<F> out;
        const std::size_t n = std::size_t{1} << coords.size();
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) out.push_back(eq_poly(i));
        return out;
    }
    //eq_weights()和multilinear.hpp种eval_eq算出来的结果一样
    //[(1-x0)(1-x1),(1-x0)x1,x1(1-x0),x0x1]
};

} // namespace whir::algebra
