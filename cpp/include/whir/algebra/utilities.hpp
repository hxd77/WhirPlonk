#pragma once

// 对应 WHIR 中的 src/algebra/mod.rs 顶层自由函数。
// 纯顺序版本, 未引入 rayon 的并行分支, 逻辑和 Rust 单线程分支完全一致。
//
//   geometric_sequence(base, length)    —— (1, base, base^2, ...) 共 length 项
//   dot / mixed_dot                     —— 内积
//   tensor_product                      —— 张量积
//   scalar_mul_add / mixed_scalar_mul_add —— 原地 acc += weight * vec
//   univariate_evaluate / mixed_univariate_evaluate —— 单变量 Horner 求值(倒序扫系数)
//   geometric_accumulate                —— acc[i] += sum_j scalars[j] * points[j]^i
//   lift                                —— 把 Source 向量映射到 Target 向量

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

template <typename F>
std::vector<F> geometric_sequence(const F& base, std::size_t length) {
    //base表示公比,length表示长度
    std::vector<F> out; //创建一个空的vector用于存放结果
    out.reserve(length); //预分配内存
    F current = F::one(); 
    for (std::size_t i = 0; i < length; ++i) {
        out.push_back(current);
        current *= base;
    }
    return out; //[1,b,b^2,...]
}

//混合点积(处理不同类型)
template <typename M> //M要求要有Target属性,函数返回M::Target
typename M::Target mixed_dot(
    const M& emb,
    std::span<const typename M::Target> a, //span是一段连续的内存
    std::span<const typename M::Source> b
) {
    using Tgt = typename M::Target; //Tgt是简短别名
    assert(a.size() == b.size()); 
    Tgt acc{}; //用{}初始化累加器acc

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
        acc = acc + emb.mixed_mul(a[i], b[i]); //相乘然后相加
    }
    return acc; //acc=acc+ a*b
}

//点积,处理恒等类型
template <typename F>
F dot(std::span<const F> a, std::span<const F> b) {
    Identity<F> id;
    return mixed_dot<Identity<F>>(id, a, b);
}


//用于计算张量积,将a中每一个元素与b中所有元素相乘
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

//将一个数组中的所有元素Lift或Map为另一种类型
template <typename M> //M类型要求包含Source和Target
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


//混合标量乘法并累加(不同类型)
template <typename M>
void mixed_scalar_mul_add(
    const M& emb,
    std::span<typename M::Target> accumulator, //累加器
    typename M::Target weight, //一个单一的标量值
    std::span<const typename M::Source> vector_ //源数组
) {
    assert(accumulator.size() == vector_.size());
#ifdef _OPENMP
    #pragma omp parallel for if(vector_.size() >= 4096)
#endif
    for (std::ptrdiff_t pi = 0; pi < static_cast<std::ptrdiff_t>(vector_.size()); ++pi) {
        const std::size_t i = static_cast<std::size_t>(pi);
        accumulator[i] = accumulator[i] + emb.mixed_mul(weight, vector_[i]);
    }//原数组*weight再加累加器中的值到累加器中
    //返回a+=a*weight
}

//混合标量乘法并相加(同一种类型)
template <typename F>
void scalar_mul_add(std::span<F> accumulator, F weight, std::span<const F> vector_) {
    Identity<F> id;
    mixed_scalar_mul_add<Identity<F>>(id, accumulator, weight, vector_);
}

//计算一元多项式在某一点的值(不同类型)
//Horner 求值, 与 Rust 顺序分支对齐: 从最后一项往前扫,每次 acc = acc * point + coeff。
//P(x) = 2 + 3x + 4x^2 + 5x^3 = 2 + x \cdot (3 + x \cdot (4 + x \cdot 5))
template <typename M>
typename M::Target mixed_univariate_evaluate(
    const M& emb,
    std::span<const typename M::Source> coefficients, //多项式系数数组
    typename M::Target point //公式里的x值
) {
    using Tgt = typename M::Target;
    //如果系数数组为空，代表多项式为0，直接返回0
    if (coefficients.empty()) return Tgt{};

    //初始化累加器acc
    //取出数组最后一位(最高次项系数,并通过map为Target类型)
    Tgt acc = emb.map(coefficients.back()); 
    for (std::size_t i = coefficients.size() - 1; i > 0; --i) {
        // 霍纳法则的第一步：将当前的累加值乘以自变量 point (x)
        acc *= point; 
        
        // 霍纳法则的第二步：加上低一次的系数 c_{i-1}。
        // 因为 acc 是 Target 类型，而系数是 Source 类型，所以调用 mixed_add
        acc = emb.mixed_add(acc, coefficients[i - 1]);
    }
    return acc;
}

//计算一元多项式在某一点的值(相同类型)
template <typename F>
F univariate_evaluate(std::span<const F> coefficients, F point) {
    Identity<F> id;
    return mixed_univariate_evaluate<Identity<F>>(id, coefficients, point);
    //假如这里F=Goldilocks64,那么返回的是mixed_univariate_evaluate<Identity<Goldilocks64>>(id, coefficients, point);
}

//几何级数累加
//acc[i] += sum_j scalars[j] * points[j]^i。
//实现与 Rust 顺序版逐步一致: 每个 entry 读入 scalars[j], 然后把 scalars[j] 乘上 points[j] 进位到下一步。
//假设scalar=[10,5],points=[2,3],acculumator=[0,0,0]
template <typename F>
void geometric_accumulate(
    std::span<F> accumulator, //累加器
    std::vector<F> scalars,     //初始标量
    std::span<const F> points //公比数组
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
        
        // 内层循环：遍历每一组数列（共 N 组）
        for (std::size_t j = 0; j < scalars.size(); ++j) {
            
            // 1. 将当前的标量值累加到当前的 accumulator 位置上
            entry = entry + scalars[j];
            
            // 2. 将当前的标量乘以对应的公比，"滚动"到等比数列的下一项
            // 这也是你注释里提到的关键点
            scalars[j] = scalars[j] * points[j]; 
        }
    }
    //第一层循环输出accumulator=[15,0,0],scalar=[20,15]
    //第二层输出accumulator=[15,35,0] ,scalar=[40,45]
    //第三层accumulator 变为 [15, 35, 85]
}

} // namespace whir::algebra
