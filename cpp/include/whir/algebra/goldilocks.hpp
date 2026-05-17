#pragma once //只包含头文件一次

//对应WHIR中的field.rs
#include <cstdint>
#include <cstdlib>
#include <ostream>

// ---- 内联汇编优化的 Montgomery 乘 ----
#ifdef __x86_64__
#include <x86intrin.h>  // MULX intrinsic (可选, 我们用纯 asm)
#endif

namespace whir::algebra {

// 前置声明 (实现在类后面, x86_64 用内联汇编)
inline uint64_t mont_mul_c(uint64_t a, uint64_t b);
#if defined(__x86_64__) && !defined(_WIN32)
inline uint64_t mont_mul_asm(uint64_t a, uint64_t b);
#define mont_mul(a, b) mont_mul_asm(a, b)
#else
#define mont_mul(a, b) mont_mul_c(a, b)
#endif

// Goldilocks prime field:
//   p = 2^64 - 2^32 + 1 = 18446744069414584321
//   multiplicative generator g = 7
//   2-adicity = 32   (p - 1 = 2^32 * (2^32 - 1))
//
// 规范内部表示：取值范围为[0, p)的uint64_t类型数值
class Goldilocks { 
public:
    //static表示静态全局常量,constexpr表示常量表达式,告诉编译器请在编译代码时就把这个数字处理好，不需要消耗任何计算资源来生成实现零成本。
    static constexpr uint64_t MODULUS = 0xFFFFFFFF00000001ULL; //ULL表示Unsigned Long Long (无符号长长整数) 2^64-2^32+1
    static constexpr uint64_t EPSILON = 0xFFFFFFFFULL;   // 2^32 - 1 = 2^64 - p
    //2^64=2^32-1 
    //2^96=2^64*2^32=(2^32-1)*2^32=2^64-2^32=2^32-1-2^32=-1(mod p   )
    static constexpr uint64_t GENERATOR = 7;
    static constexpr uint32_t TWO_ADICITY = 32; //乘法群里存在阶为2^k的本原单位根

    static constexpr double field_size_bits = 64.0;

    constexpr Goldilocks() noexcept : v_(0) {} //默认构造函数 noexcept:一个安全承诺，明确告诉编译器这个函数绝对不会抛出任何异常

    static constexpr Goldilocks from_u64(uint64_t v) noexcept { //外部传入unit64_t可能大于等于p
        // v ＜ 2^64 ＜ 2p，因此一次条件减法即可满足要求.
        return Goldilocks{v >= MODULUS ? v - MODULUS : v}; 
    }
    static constexpr Goldilocks zero() noexcept { return Goldilocks{}; }
    static constexpr Goldilocks one() noexcept { return Goldilocks{1}; }

    // 从随机数生成器采样 (用于 ZK 盲化多项式)
    template <typename Rng>
    static Goldilocks random(Rng& rng) {
        return from_u64(rng.next());
    }

    constexpr uint64_t as_canonical_u64() const noexcept { return v_; } //常量成员函数,返回uint64_t的数字v_
    constexpr bool is_zero() const noexcept { return v_ == 0; }

    friend constexpr bool operator==(Goldilocks a, Goldilocks b) noexcept { //友元函数，可以访问类中的私有成员 
        return a.v_ == b.v_; //相等函数
    }
    friend constexpr bool operator!=(Goldilocks a, Goldilocks b) noexcept {
        return a.v_ != b.v_; //不相等
    }

    friend constexpr Goldilocks operator+(Goldilocks a, Goldilocks b) noexcept { //相加
        uint64_t sum = a.v_ + b.v_;
        // 对（和小于a.v_ 或 和大于等于p）的情况进行规整：通过减去p实现标准化处理。
        if (sum < a.v_ || sum >= MODULUS) { //两个数[0,p-1)相加最大约等于2p-2<2^65 如果sum<a.v_说明发生了unit64_t硬件溢出
            sum -= MODULUS; //就算发生了硬件溢出变成了a+b-2^64，但是由于减去p之后变成了一个负数但是uint64_t不允许是一个负数，所以会自动加上一个2^64,所以其实是a+b-p
        }
        return Goldilocks{sum};
    }

    friend constexpr Goldilocks operator-(Goldilocks a) noexcept { //取负
        return Goldilocks{a.v_ == 0 ? 0 : MODULUS - a.v_};
    }

    friend constexpr Goldilocks operator-(Goldilocks a, Goldilocks b) noexcept { //减法
        if (a.v_ >= b.v_) {
            return Goldilocks{a.v_ - b.v_};
        }
        // a < b: result = (a + p) - b, fits in [0, p).
        return Goldilocks{(MODULUS - b.v_) + a.v_};
    }

    friend Goldilocks operator*(Goldilocks a, Goldilocks b) noexcept {
        return Goldilocks{reduce128(__uint128_t{a.v_} * b.v_)};
    }

    //原地更改操作
    Goldilocks& operator+=(Goldilocks o) noexcept { *this = *this + o; return *this; } 
    Goldilocks& operator-=(Goldilocks o) noexcept { *this = *this - o; return *this; }
    Goldilocks& operator*=(Goldilocks o) noexcept { *this = *this * o; return *this; }

    //平方
    Goldilocks square() const noexcept { return *this * *this; }

    // 使用u64类型指数的二进制幂运算 快速幂
    Goldilocks pow(uint64_t exp) const noexcept {
        Goldilocks result = one();
        Goldilocks base = *this;
        while (exp > 0) {
            if (exp & 1u) result *= base;
            exp >>= 1;
            if (exp > 0) base = base.square();
        }
        return result;
    }

    // 通过费马小定理求乘法逆元：a^(p-2)。费马小定理a^(p-1)=1(mod p)
    // 前置条件：*this 不等于 0（否则返回 0，与 0^(p-2) = 0 保持一致）。
    Goldilocks inverse() const noexcept {
        return pow(MODULUS - 2); //求逆元
    }

    //计算Goldilocks域上的本原2^k次单位根  k代表你想要的单位根的阶数以2为底的对数
    //乘法群F_p的阶是p-1=2^64 − 2^32 = 2^32 · (2^32 − 1) = 2^TWO_ADICITY · EPSILON
    static Goldilocks two_adic_root_of_unity(uint32_t k) noexcept {
        if (k > TWO_ADICITY) std::abort(); //群的阶p-1最多只能被2^32整除,所以F_p里不存在阶为2^33或更大的2次幂单位根
        uint64_t exp = (static_cast<uint64_t>(1) << (TWO_ADICITY - k)) * EPSILON; //exp=2^(32-k)*(2^32-1)
        //因为想让阶为2^k，如果g是乘法群的生成元（阶为p-1）,那么子群g^(p-1)/2^k的阶就是2^k，所以我们要计算出(p-1)/2^k
        //p-1=2^32*(2^32-1),所以原式=2^32*(2^32-1)/2^k=2^(32-k)*(2^32-1)=exp
        return Goldilocks::from_u64(GENERATOR).pow(exp);
    }

    friend std::ostream& operator<<(std::ostream& os, Goldilocks x) { //std::ostream& 返回流本身的引用 os.operaotr<<(Goldilocks)运算符<<重载为非成员函数
        return os << x.v_;
    }

private:
    explicit constexpr Goldilocks(uint64_t v) noexcept : v_(v) {} //带参构造函数,传入一个64位无符号整数，生成一个Goldilocks域元素 explicit防止隐式类型转换

    // 快速实现128位乘积对模数p的约简
    static uint64_t reduce128(__uint128_t x) noexcept { //x<p^2<2^128
        uint64_t lo = static_cast<uint64_t>(x); //低64位: x的[0,64)位
        uint64_t hi = static_cast<uint64_t>(x >> 64); //高64位: x的[64,128)位
        uint32_t hi_hi = static_cast<uint32_t>(hi >> 32); //x的[96,128)位
        uint32_t hi_lo = static_cast<uint32_t>(hi); //x的[64,96)位

        //x=hi_hi*2^96+hi_lo*2^64+lo=hi_hi*-1+hi_lo*EPSILON+lo=(lo-hi_hi)+hi_lo*EPSILON
        // t0 = (lo - hi_hi) mod p, in [0, p).
        uint64_t t0;
        if (lo >= hi_hi) {
            t0 = lo - hi_hi;
        } else {
            t0 = MODULUS - (static_cast<uint64_t>(hi_hi) - lo); //把hi_hi转换成64位
        }

        // t1 = hi_lo * (2^32 - 1). Max value = (2^32 - 1)^2 < p. //hi_lo<2^32 EPSILON=2^32-1<2^32 乘积<(2^32)^2=2^64，不溢出uint64_t
        uint64_t t1 = static_cast<uint64_t>(hi_lo) * EPSILON;

        // t2 = (t0 + t1) mod p. Both t0, t1 are in [0, p), so t0 + t1 < 2p.
        uint64_t sum = t0 + t1;
        if (sum < t0 || sum >= MODULUS) {
            // 溢出表示真实数值大于等于$2^{64}$且大于模数$p$，需减去对$2^{64}$取模后的$p$（等价于负的极小值常量）。
            sum -= MODULUS; //第一种情况发生了溢出uint64_t，sum=真值-2^64，因为
        }
        return sum; //64位+64位=64位
    }

    uint64_t v_;
};

// =========================================================================
// 优化的 Montgomery 乘法 (内联, Goldilocks 域专用)
//
// 使用 Goldilocks 的 p = 2^64 - 2^32 + 1 和 μ = 2^32 - 1 做快速约简.
// x86_64 上用 MULX 指令, 其他平台用 __uint128_t.
// =========================================================================

/// 纯 C++ 优化版 (所有平台可用, ~15 cycles)
inline uint64_t mont_mul_c(uint64_t a, uint64_t b) {
    __uint128_t p = __uint128_t{a} * b;
    uint64_t lo = static_cast<uint64_t>(p);
    uint64_t hi = static_cast<uint64_t>(p >> 64);

    // t = lo * μ mod 2^64, where μ = 2^32 - 1 = 0xFFFFFFFF
    uint64_t t = lo * 0xFFFFFFFFULL;

    // r = hi + t + (lo + t overflowed ? 1 : 0)
    uint64_t r = hi + t + (static_cast<uint64_t>(lo + t) < lo);

    // r -= t>>32; Goldilocks 特殊: t*p = t*2^64 - t*2^32 + t
    uint64_t sub = t >> 32;
    if (r < sub) {
        r = r - sub + 0xFFFFFFFF00000001ULL;
    } else {
        r -= sub;
        if (r >= 0xFFFFFFFF00000001ULL) r -= 0xFFFFFFFF00000001ULL;
    }
    return r;
}

#if defined(__x86_64__) && !defined(_WIN32)
// x86_64 内联汇编版 (~6-8 cycles, MULX + 标志位链)
__attribute__((always_inline))
inline uint64_t mont_mul_asm(uint64_t a, uint64_t b) {
    uint64_t r;
    asm volatile(
        "mulx %1, %0, %%rdx\n\t"   // rdx:r0 = a*b;  r0=lo, rdx=hi
        "mov %0, %%r8\n\t"         // r8 = lo
        "shl $32, %%r8\n\t"        // r8 = lo<<32
        "sub %0, %%r8\n\t"         // r8 = (lo<<32)-lo = t
        "mov %%r8, %%r9\n\t"       // r9 = t
        "add %%r8, %0\n\t"         // r0 = lo+t, CF=overflow
        "setc %%cl\n\t"            // cl = carry(lo+t)
        "add %%r8, %%rdx\n\t"      // rdx = hi+t  (CF changed, but carry saved)
        "movzbq %%cl, %%r8\n\t"    // r8 = zero-extend(carry)
        "add %%r8, %%rdx\n\t"      // rdx += carry
        "shr $32, %%r9\n\t"        // r9 = t>>32
        "sub %%r9, %%rdx\n\t"      // rdx -= sub
        "jnc 0f\n\t"               // no borrow → skip +p
        "mov $0xFFFFFFFF00000001, %%r8\n\t"
        "add %%r8, %%rdx\n\t"      // rdx += p
        "jmp 1f\n"
        "0: mov $0xFFFFFFFF00000001, %%r8\n\t"
        "cmp %%r8, %%rdx\n\t"
        "jb 1f\n\t"
        "sub %%r8, %%rdx\n"        // rdx -= p
        "1: mov %%rdx, %0\n"       // r = rdx
        : "=r"(r)
        : "r"(a), "r"(b)
        : "rdx", "rcx", "r8", "r9", "cc", "memory");
    return r;
}
#define mont_mul(a, b) mont_mul_asm(a, b)
#else
#define mont_mul(a, b) mont_mul_c(a, b)
#endif

} // namespace whir::algebra
