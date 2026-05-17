#pragma once

// 对应 WHIR 中的 src/algebra/sumcheck.rs。
//   compute_sumcheck_polynomial   —— 返回二次项和常数项 (acc0, acc2)
//   fold                          —— 在 weight 处做线性插值并原地折半
//   mixed_eval                    —— 把 coeff(长度 2^k) 在多线性点 eval 上求值, 系数来自 Source 域

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

//计算Prover需要发送给Verifier的一元多项式的特定系数或求值 
//A(X) = A(0) + X * (A(1) - A(0))
//B(X) = B(0) + X * (B(1) - B(0))
//P(X) = C_0 + C_1X + C_2X^2, X^2的系数正好是(A(1) - A(0)) *(B(1) - B(0))
template <typename F>
std::pair<F, F> compute_sumcheck_polynomial(
    std::span<const F> a,
    std::span<const F> b
) {
    assert(a.size() == b.size());
    const std::size_t half = a.size() / 2;

    //将a和b各自拆分为前半部分(X=0的分支)和后半部分(X=1的分支)
    auto a0 = a.subspan(0, half); //a的前半段
    auto a1 = a.subspan(half);
    auto b0 = b.subspan(0, half);
    auto b1 = b.subspan(half);
    assert(a0.size() == a1.size());
    assert(b0.size() == b1.size());
    assert(a0.size() == b0.size());

    F acc0{}; //初始化acc0,用于累加P(0)
    F acc2{}; //初始化acc2,用于累加二次项系数

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
        //计算P(0): 直接将X=0的对应项相乘并累加
        acc0 += a0[i] * b0[i];

        //计算X^2的系数
        acc2 += (a1[i] - a0[i]) * (b1[i] - b0[i]);
    }
    return {acc0, acc2};
}

//按权重执行线性插值,并将数组长度减半
//在权重 weight 处做线性插值: low[i] += (high[i] - low[i]) * weight, 然后把 values 截断到前半部分。
template <typename F>
void fold(std::vector<F>& values, F weight) {
    assert(values.size() % 2 == 0); //长度为偶数
    const std::size_t half = values.size() / 2;
#ifdef _OPENMP
    #pragma omp parallel for if(half >= 4096)
#endif
    for (std::size_t i = 0; i < half; ++i) {
        values[i] = values[i] + (values[half + i] - values[i]) * weight;
    }
    //将数组大小截断为half
    values.resize(half);
    //释放被抛弃部分的内存 
}

//计算一个多变量的多线性在特定点的值 
//把长度 2^k 的系数向量 coeff(在 Source 域) 看作布尔超立方上的多元系数,
//对多线性点 eval(在 Target 域) 求值, 并乘上 scalar。与 Rust 的 mixed_eval 行为对齐。
//例子:f(x_0, x_1) = c_0 + c_1x_1 + c_2x_0 + c_3x_0x_1
template <typename M>
typename M::Target mixed_eval(
    const M& emb,
    std::span<const typename M::Source> coeff,
    std::span<const typename M::Target> eval, //eval包含所有自变量的值(即要代入的求指点数组[x0,x1,...,x_n-1])
    typename M::Target scalar //累积的标量乘数,一般为1
) {
    using Tgt = typename M::Target; 
    //确保系数数组长度等于2的n次方(n是变量个数)
    assert(coeff.size() == (std::size_t{1} << eval.size()));

    //当所有变量
    if (eval.empty()) {
        return emb.mixed_mul(scalar, coeff[0]);
    }

    //取出当前维度的变量x_0
    const Tgt x = eval[0];
    //tail剩下x_1
    const auto tail = eval.subspan(1);
    const std::size_t half = coeff.size() / 2;
    const auto low  = coeff.subspan(0, half);
    const auto high = coeff.subspan(half);

    // 【递归调用】
    // a 分支 (低位)：处理 [c0, c1]，变量用剩下的 [x_1]，标量保持不变 (传下去 1)
    const Tgt a = mixed_eval<M>(emb, low,  tail, scalar);

    // b 分支 (高位)：处理 [c2, c3]，变量用剩下的 [x_1]，
    // 关键点：标量乘上了当前的 x_0 (传下去 1 * x0)
    const Tgt b = mixed_eval<M>(emb, high, tail, scalar * x);

    // 返回合并结果： (c0 + c1*x1) + (c2*x0 + c3*x0*x1)
    return a + b;
}

} // namespace whir::algebra
