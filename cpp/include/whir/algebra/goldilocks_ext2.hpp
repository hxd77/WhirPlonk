#pragma once

#include "goldilocks.hpp"

namespace whir::algebra {

// 基于Goldilocks素数域构造二次扩域 Fp2 = Fp[X] / (X² - 7)。 //X^2-7表示遇到X^2-7当作0，或把X^2替换成7
//为什么选X^2-7,因为7是一个二次非剩余，在mod p条件下，找不到任意一个数字x使得x^2=7(mod p)
// 元素结构：c0 + c1*X。
// 与 ark-ff 库中 src/algebra/fields.rs 文件内的 F2Config64 配置保持一致（二次非剩余元取值为 7）。
class GoldilocksExt2 { //是一个a+bx a和b都属于[0,p)
public:
    using BaseField = Goldilocks; //基域别名，供 Embedding / Basefield 模板使用
    static constexpr uint64_t NONRESIDUE = 7;
    static constexpr double field_size_bits = 128.0;

    constexpr GoldilocksExt2() noexcept = default;
    constexpr GoldilocksExt2(Goldilocks c0, Goldilocks c1) noexcept
        : c0_(c0), c1_(c1) {}

    static constexpr GoldilocksExt2 zero() noexcept { //(0,0)
        return {Goldilocks::zero(), Goldilocks::zero()};
    }
    static constexpr GoldilocksExt2 one() noexcept { //(1,0)
        return {Goldilocks::one(), Goldilocks::zero()};
    }

    template <typename Rng>
    static GoldilocksExt2 random(Rng& rng) {
        return {Goldilocks::random(rng), Goldilocks::random(rng)};
    }
    static constexpr GoldilocksExt2 from_base(Goldilocks a) noexcept { //(a,0)
        return {a, Goldilocks::zero()};
    }
    static constexpr GoldilocksExt2 from_u64(uint64_t v) noexcept {
        return from_base(Goldilocks::from_u64(v));
    }

    constexpr Goldilocks c0() const noexcept { return c0_; } //返回c0_
    constexpr Goldilocks c1() const noexcept { return c1_; }

    friend constexpr bool operator==(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept { //判断两个数是否相等
        return a.c0_ == b.c0_ && a.c1_ == b.c1_;
    }
    friend constexpr bool operator!=(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept { //判断两个数不相等
        return !(a == b);
    }

    friend constexpr GoldilocksExt2 operator+(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept { //两数相加
        return {a.c0_ + b.c0_, a.c1_ + b.c1_};
    }
    friend constexpr GoldilocksExt2 operator-(const GoldilocksExt2& a) noexcept { //取反
        return {-a.c0_, -a.c1_};
    }
    friend constexpr GoldilocksExt2 operator-(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept { //两数相减
        return {a.c0_ - b.c0_, a.c1_ - b.c1_};
    }

    // (a0 + a1 X)(b0 + b1 X) = (a0 b0 + NR a1 b1) + (a0 b1 + a1 b0) X
    //乘法: (a_1 + b_1X) * (a_2 + b_2X) = a_1a_2 + a_1b_2X + b_1a_2X + b_1b_2X^2, 把X^2换成7
    friend GoldilocksExt2 operator*(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept {
        Goldilocks nr = Goldilocks::from_u64(NONRESIDUE);
        Goldilocks out0 = a.c0_ * b.c0_ + nr * (a.c1_ * b.c1_);
        Goldilocks out1 = a.c0_ * b.c1_ + a.c1_ * b.c0_;
        return {out0, out1};
    }

    //原地操作
    GoldilocksExt2& operator+=(const GoldilocksExt2& o) noexcept { *this = *this + o; return *this; }
    GoldilocksExt2& operator-=(const GoldilocksExt2& o) noexcept { *this = *this - o; return *this; }
    GoldilocksExt2& operator*=(const GoldilocksExt2& o) noexcept { *this = *this * o; return *this; }

    //平方
    GoldilocksExt2 square() const noexcept { return *this * *this; }

    //快速幂
    GoldilocksExt2 pow(uint64_t exp) const noexcept {
        GoldilocksExt2 result = one();
        GoldilocksExt2 base = *this;
        while (exp > 0) {
            if (exp & 1u) result *= base;
            exp >>= 1;
            if (exp > 0) base = base.square();
        }
        return result;
    }

    // 求乘法逆元 1/a+bi=a-bi/(a+bi)(a-bi)=a-bi/a^2+b^2
    //假设元素是c0+c1X,它的共轭为c0-c1X,逆元为1/c0+c1X,分子分母同乘上共轭
    //所以分母(c_0 + c_1X)(c_0 - c_1X) = c_0^2 - c_1^2X^2=c_0^2-7c_1^2
    //   (c0 + c1 X)(c0 - c1 X) = c0^2 - NR * c1^2
    GoldilocksExt2 inverse() const noexcept {
        Goldilocks nr = Goldilocks::from_u64(NONRESIDUE);
        Goldilocks norm = c0_ * c0_ - nr * (c1_ * c1_);
        Goldilocks norm_inv = norm.inverse(); //原本基础域中的求逆
        return {c0_ * norm_inv, -(c1_ * norm_inv)}; 
    }

    //Frobenius映射,用来计算元素的p次方 k代表你想要对当前扩域元素应用Frobenius映射的次数相当于求当前元素的p^k次方即x^(p^k) p是模数
    // 假设元素是x=c0+c1X,要求p次方(c0+c1X)^p,
    //在特征为 p 的有限域里，有一个著名的定理叫 “新生之梦”（Freshman's Dream）(A + B)^p \equiv A^p + B^p \pmod p。
    //中间所有的交叉项都会被 p 整除而消失。所以式子变成了：c_0^p + c_1^p X^p接着，根据费马小定理，基础域里的任何元素 a 都满足 a^p \equiv a \pmod p。
    //因为 c_0和 c_1$都是基础域元素，所以 c_0^p = c_0，c_1^p = c_1。式子进一步简化为：c_0 + c_1 X^p
    //现在最大的问题是，X^p是多少？我们知道 X^2 = 7。把 X^p 拆开：X^p = X * X^{p-1} = X *(X^2)^{\frac{p-1}{2}} = X * 7^{\frac{p-1}{2}}
    //因为 7 是这个域里的“非二次剩余”，根据欧拉准则（Euler's Criterion），$7^{\frac{p-1}{2}} \equiv -1 \pmod p$。所以，$X^p = X \cdot (-1) = -X$。
    //结论：在二次扩域中，求一个元素的 $p$ 次方，结果就是它的共轭！(c_0 + c_1X)^p = c_0 - c_1X
   // 第二步：应用 $k$ 次 Frobenius 映射现在我们知道：应用 1 次（求 $p^1$ 次方）：变成共轭 $c_0 - c_1X$。应用 2 次（求 $p^2$ 次方）：对共轭再求共轭，
   //负负得正，又变回了原样 $c_0 + c_1X$。应用 3 次：再次变成共轭。规律非常明显了：只要 $k$ 是偶数，元素保持不变；只要 $k$ 是奇数，元素变成共轭。
    GoldilocksExt2 frobenius_map(uint64_t k) const noexcept {
        if ((k & 1u) == 0) return *this; //如果结果等于0说明k是偶数
        return {c0_, -c1_}; //否则k是奇数
    }

private:
    Goldilocks c0_;
    Goldilocks c1_;
};

} // namespace whir::algebra
