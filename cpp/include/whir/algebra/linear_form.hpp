#pragma once

// 对应 WHIR 中的 src/algebra/linear_form/*.rs。
// Rust 里 LinearForm<F> 是一个 trait, 这里用抽象基类 + 虚函数实现 dyn LinearForm<F>。
// Evaluate<M> 在 Rust 里是第二个 trait, 因为 embedding 的类型参数没法虚函数化,
// 所以 C++ 侧把 evaluate 做成每个具体子类上的模板方法(非虚)。
//
// 三种具体 LinearForm:
//   Covector<F>               —— 显式的覆向量, 线性泛函 ⟨w, v⟩
//   MultilinearExtension<F>   —— 固定点 point 处的多元线性扩张求值
//   UnivariateEvaluation<F>   —— 在点 x 处做单变量多项式求值: sum_i v_i * x^i

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
    virtual ~LinearForm() = default; //虚析构函数
    virtual std::size_t size() const = 0; //多项式在布尔超立方体上的大小，一般是2^n
    virtual F mle_evaluate(std::span<const F> point) const = 0; //计算多项式MLE在给定point上的值
    virtual void accumulate(std::span<F> accumulator, F scalar) const = 0;
};

//一个线性形式，即从向量空间到标量域的一个线性映射
//表示f(x1​,x2​,...,xn​)=v1​x1​+v2​x2​+...+vn​xn​
template <typename F>
class Covector final : public LinearForm<F> {
public:
    std::vector<F> vector; //和 Rust 的 pub vector: Vec<F> 对齐

    Covector() = default;
    explicit Covector(std::vector<F> v) : vector(std::move(v)) {} //Covecotr内存存一个vector,代表在单位超立方体求值点上的一组值 virtual虚函数动态绑定

    //把任意 LinearForm<F> 物化成 Covector: 对单位向量调 accumulate。
    static Covector from_linear_form(const LinearForm<F>& lf) {
        std::vector<F> v(lf.size(), F{}); //F{} 对应 F::ZERO
        lf.accumulate(v, F::one()); //对每个基向量ei调用accumulate
        return Covector{std::move(v)}; //
    }

    std::size_t size() const override { return vector.size(); } //向量长度 override要求是在重写父类基函数，如果不是就报错

    F mle_evaluate(std::span<const F> point) const override { //输入一个点
        return multilinear_extend<F>(std::span<const F>{vector}, point); //返回恒等类型的在point上的值
    }

    void accumulate(std::span<F> accumulator, F scalar) const override {
        scalar_mul_add<F>(accumulator, scalar, std::span<const F>{vector});
        //返回acc=acc+scalar*v
    }

    //在 Embedding 下求值: ⟨w, v⟩, 其中 w 在 Target 域, v 在 Source 域。
    template <typename M>
    typename M::Target evaluate(
        const M& emb,
        std::span<const typename M::Source> vec
    ) const {
        static_assert(std::is_same_v<F, typename M::Target>, 
            "Covector::evaluate: M::Target 必须是本 Covector 的 F"); //static_assert强制检查类内部的数据类型F是否和M要求输出类型M::Target一致
        assert(vector.size() == vec.size());
        return mixed_dot<M>(emb, std::span<const F>{vector}, vec); //acc+=vector*vec
    }
};

//固定点 point 处的多元线性扩张求值
template <typename F>
class MultilinearExtension final : public LinearForm<F> { //final表示禁止继承
public:
    std::vector<F> point;

    MultilinearExtension() = default; 
    explicit MultilinearExtension(std::vector<F> p) : point(std::move(p)) {} //初始化 

    std::size_t size() const override { return std::size_t{1} << point.size(); } //override要求重写父类的的虚函数

    //Rust: zip_strict(self.point, point).fold(ONE, |acc, (l, r)| acc * (l*r + (1-l)*(1-r)))
    //MLE求值: 实现相等多项式
    F mle_evaluate(std::span<const F> pt) const override { 
        assert(point.size() == pt.size());
        F acc = F::one();
        for (std::size_t i = 0; i < point.size(); ++i) {
            const F l = point[i];
            const F r = pt[i];
            acc = acc * (l * r + (F::one() - l) * (F::one() - r));
        }
        return acc; 
        //返回计算eq(x, y) = ( x_i*y_i + (1 - x_i)(1 - y_i)的结果 
    }

    void accumulate(std::span<F> accumulator, F scalar) const override {
        eval_eq<F>(accumulator, std::span<const F>{point}, scalar);
    } //返回[ (1-x0)(1-x1),  (1-x0)x1,  x0(1-x1),  x0x1 ]   基多项式 

    template <typename M>
    typename M::Target evaluate(
        const M& emb,
        std::span<const typename M::Source> vec
    ) const {
        static_assert(std::is_same_v<F, typename M::Target>,
            "MultilinearExtension::evaluate: M::Target 必须是本 MLE 的 F");
        return mixed_multilinear_extend<M>(emb, vec, std::span<const F>{point}); //计算MLE在point上的值
    }
};

//单变量多项式求值: v_0 + v_1 x + v_2 x^2 + ... 在点 x 处
//将单变量多项式的连续幂次向量，映射到多元线性空间中进行求值
template <typename F>
class UnivariateEvaluation final : public LinearForm<F> {
public:
    std::size_t size_value; //Rust 里名字叫 size, 这里避开和基类方法重名
    F point;                //评估点 x

    UnivariateEvaluation() : size_value(0), point{} {}
    UnivariateEvaluation(F x, std::size_t s) : size_value(s), point(x) {}

    std::size_t size() const override { return size_value; }

    //(1, x, x^2, ...) 的多元线性扩张 = ⨂_i (1, x^{2^i}) 的张量积在点 pt 上求值。
    //Rust 代码从后往前遍历 pt, 并在每一步把 x2i 自平方。
    F mle_evaluate(std::span<const F> pt) const override { //传入一个n维的坐标点r=(r_n-1,...,r1,r0) ,假设传pt=(3,4)
        F x2i = point; //x2i代表x^(2^i)
        F result = F::one(); 
        //逆序
        for (auto it = pt.rbegin(); it != pt.rend(); ++it) {
            
            //假设传入r=[r1,r0]
            const F r = *it; //先取r0=4,再取r1=3
            result *= (F::one() - r) + r * x2i; //在布尔空间里,如果r=0则结果是1，当r=1时，结果是x^(2^i)
            x2i = x2i * x2i; //square_in_place
        }
        return result;
        //Result = [ (1-r_0) + r_0 · x ] * [ (1-r_1) + r_1 · x^2 ]
        //展开后 = (1-r_1)(1-r_0) · 1 + (1-r_1)r_0 · x + r_1(1-r_0) · x^2 + r_1 r_0 · (x ·x^2)
        // = (1-r_1)(1-r_0)·1 + (1-r_1)r_0·x + r_1(1-r_0)·x^2 + r_1 r_0·x^3
        
        //V = (1,x,x^2,x^3)
        //MLE = V_0·(1-r_1)(1-r_0) + V_1·(1-r_1)r_0 + V_2 ·r_1(1-r_0) + V_3 ·r_1 r_0
        //MLE =1·(1-r_1)(1-r_0) + x ·(1-r_1)r_0 + x^2 ·r_1(1-r_0) + x^3 ·r_1 r_0
        //跟上面result计算结果一样
    }

    //把我们前面讲的那个连续幂次向量 V = (1, x, x^2,...)，整体乘以一个缩放因子（scalar），然后“叠加”到一个外部传进来的大数组（accumulator）里面去。
    //A -> A + s * (1, x, x^2, x^3,...)
    //accumulator[i] += scalar * point^i
    void accumulate(std::span<F> accumulator, F scalar) const override {
        assert(accumulator.size() == size_value);
        F power = scalar;
        for (auto& entry : accumulator) {
            entry = entry + power;
            power = power * point;
        }
    }

    //将多个单变量多项式的评估通过随机线性组合折叠/合并成一个单一的结果
    //批量版: 对多个 UnivariateEvaluation, 共用同一个 accumulator, 用 geometric_accumulate 合并。
    static void accumulate_many(
        const std::vector<UnivariateEvaluation>& evaluators, //不同的单变量评估器集合(一个包含了多个UnivariateEvaluation对象的列表)
        std::span<F> accumulator, //累加器
        std::span<const F> scalars //缩放因子(size=evaluators.size()
    ) {
        assert(evaluators.size() == scalars.size());
        if (evaluators.empty()) return;

        const std::size_t size_check = evaluators.front().size_value; //每个评估器的大小

        assert(accumulator.size() == size_check);
        for (const auto& e : evaluators) {
            assert(e.size_value == size_check);
        }

        std::vector<F> points;
        points.reserve(evaluators.size()); //point有size大小
        for (const auto& e : evaluators) points.push_back(e.point); //把evaluators中的point放入到数组points中

        std::vector<F> scalars_vec(scalars.begin(), scalars.end()); //把scalars数据复制到scalars_vec中
        geometric_accumulate<F>(accumulator, std::move(scalars_vec), std::span<const F>{points});//批量进行几何计算
    }

    template <typename M>
    typename M::Target evaluate(
        const M& emb,
        std::span<const typename M::Source> vec
    ) const {
        static_assert(std::is_same_v<F, typename M::Target>,
            "UnivariateEvaluation::evaluate: M::Target 必须是本对象的 F");
        return mixed_univariate_evaluate<M>(emb, vec, point); //算出多项式在point处的值
    }
};

} // namespace whir::algebra
