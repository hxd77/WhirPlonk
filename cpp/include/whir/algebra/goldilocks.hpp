#pragma once

// ============================================================================
// goldilocks.hpp — Goldilocks 素数域 Fp 运算
//
// 域定义:
//   p = 2^64 - 2^32 + 1 = 18446744069414584321
//   乘法生成元 g = 7
//   2-adicity = 32   (p - 1 = 2^32 * (2^32 - 1))
//
// 内部表示: [0, p) 范围内的 uint64_t 规范形式
//
// 约简策略:
//   对于 128 位乘积 a*b < p^2 < 2^128，利用 p 的稀疏结构实现免除法模约简:
//     设 x = hi * 2^64 + lo
//     由于 2^64 ≡ 2^32 - 1 (mod p)，有:
//       x ≡ lo + hi_lo * (2^32 - 1) - hi_hi  (mod p)
//     其中 hi = hi_hi * 2^32 + hi_lo
//   约简仅需 ~5 次算术运算
//
// Montgomery 乘法:
//   使用 Goldilocks 专用 μ = -p^{-1} mod 2^64 = 2^32 - 1
//   x86_64 路径使用 MULX + 标志位链 (~6-8 cycles)
//   通用路径使用 __uint128_t (~15 cycles)
//
// 对应 Rust: src/algebra/fields.rs (GoldilocksField)
// ============================================================================

#include <cstdint>
#include <cstdlib>
#include <ostream>

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#ifdef __x86_64__
#include <x86intrin.h>
#endif

namespace whir::algebra {

// 平台分派: Montgomery 乘法前置声明
inline uint64_t mont_mul_c(uint64_t a, uint64_t b);
#if defined(__x86_64__) && !defined(_WIN32)
inline uint64_t mont_mul_asm(uint64_t a, uint64_t b);
#define mont_mul(a, b) mont_mul_asm(a, b)
#else
#define mont_mul(a, b) mont_mul_c(a, b)
#endif

// ============================================================================
// Goldilocks 域元素
// ============================================================================
class Goldilocks {
public:
    // p = 2^64 - 2^32 + 1，选择此素数使得 p-1 具有大 2-adic 因子
    // 这使得 NTT 可以处理最多 2^32 个点的域
    static constexpr uint64_t MODULUS = 0xFFFFFFFF00000001ULL;

    // ε = 2^32 - 1 = 2^64 - p，用于快速约简: a * 2^64 ≡ a * ε (mod p)
    static constexpr uint64_t EPSILON = 0xFFFFFFFFULL;

    static constexpr uint64_t GENERATOR = 7;
    static constexpr uint32_t TWO_ADICITY = 32;
    static constexpr double field_size_bits = 64.0;

    constexpr Goldilocks() noexcept : v_(0) {}

    // 约简 v 到 [0, p)。由于 v < 2^64 < 2p，一次条件减法即可
    static constexpr Goldilocks from_u64(uint64_t v) noexcept {
        return Goldilocks{v >= MODULUS ? v - MODULUS : v};
    }

    static constexpr Goldilocks zero() noexcept { return Goldilocks{}; }
    static constexpr Goldilocks one() noexcept { return Goldilocks{1}; }

    template <typename Rng>
    static Goldilocks random(Rng& rng) {
        return from_u64(rng.next());
    }

    constexpr uint64_t as_canonical_u64() const noexcept { return v_; }
    constexpr bool is_zero() const noexcept { return v_ == 0; }

    friend constexpr bool operator==(Goldilocks a, Goldilocks b) noexcept {
        return a.v_ == b.v_;
    }
    friend constexpr bool operator!=(Goldilocks a, Goldilocks b) noexcept {
        return a.v_ != b.v_;
    }

    // 加法 + 条件减法:
    //   sum = a + b。若 sum 溢出 (sum < a) 或 sum >= p，则减去 p
    //   溢出后变为 a+b-2^64，通过无符号语义加回 2^64 得到 a+b-p
    friend constexpr Goldilocks operator+(Goldilocks a, Goldilocks b) noexcept {
        uint64_t sum = a.v_ + b.v_;
        if (sum < a.v_ || sum >= MODULUS) {
            sum -= MODULUS;
        }
        return Goldilocks{sum};
    }

    friend constexpr Goldilocks operator-(Goldilocks a) noexcept {
        return Goldilocks{a.v_ == 0 ? 0 : MODULUS - a.v_};
    }

    // 减法 + 条件加法 p，保证结果非负
    friend constexpr Goldilocks operator-(Goldilocks a, Goldilocks b) noexcept {
        if (a.v_ >= b.v_) {
            return Goldilocks{a.v_ - b.v_};
        }
        return Goldilocks{(MODULUS - b.v_) + a.v_};
    }

    // 乘法: 128 位乘积 + 快速约简
    friend Goldilocks operator*(Goldilocks a, Goldilocks b) noexcept {
#if defined(_MSC_VER) && !defined(__clang__)
        uint64_t hi = 0;
        uint64_t lo = _umul128(a.v_, b.v_, &hi);
        return Goldilocks{reduce128_parts(lo, hi)};
#else
        return Goldilocks{reduce128(__uint128_t{a.v_} * b.v_)};
#endif
    }

    Goldilocks& operator+=(Goldilocks o) noexcept { *this = *this + o; return *this; }
    Goldilocks& operator-=(Goldilocks o) noexcept { *this = *this - o; return *this; }
    Goldilocks& operator*=(Goldilocks o) noexcept { *this = *this * o; return *this; }

    Goldilocks square() const noexcept { return *this * *this; }

    // 二进制快速幂 (square-and-multiply)，O(log exp) 次乘法
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

    // 乘法逆元: Fermat 小定理 a^{-1} = a^{p-2}
    // 前置条件: *this != 0（零输入返回 0，与 0^{p-2} = 0 保持一致）
    Goldilocks inverse() const noexcept {
        return pow(MODULUS - 2);
    }

    // 返回 Fp 中的本原 2^k 次单位根
    //
    // 乘法群 Fp* 的阶为 p-1 = 2^32 * ε
    // 对于 k <= 32，元素 g^{(p-1)/2^k} 的精确阶为 2^k
    // 对于 k > 32，不存在这样的根 — 终止程序
    static Goldilocks two_adic_root_of_unity(uint32_t k) noexcept {
        if (k > TWO_ADICITY) std::abort();
        uint64_t exp = (static_cast<uint64_t>(1) << (TWO_ADICITY - k)) * EPSILON;
        return Goldilocks::from_u64(GENERATOR).pow(exp);
    }

    friend std::ostream& operator<<(std::ostream& os, Goldilocks x) {
        return os << x.v_;
    }

private:
    explicit constexpr Goldilocks(uint64_t v) noexcept : v_(v) {}

    // 利用 Goldilocks 结构的快速 128 位约简
    //
    // 设 x = hi_hi * 2^96 + hi_lo * 2^64 + lo
    // 由于 2^64 ≡ ε (mod p) 且 2^96 ≡ -1 (mod p):
    //   x ≡ lo + hi_lo * ε - hi_hi  (mod p)
    // 所有中间值在 64 位内，仅需一次条件加/减 p
    static uint64_t reduce128_parts(uint64_t lo, uint64_t hi) noexcept {
        uint32_t hi_hi = static_cast<uint32_t>(hi >> 32);
        uint32_t hi_lo = static_cast<uint32_t>(hi);

        uint64_t t0;
        if (lo >= hi_hi) {
            t0 = lo - hi_hi;
        } else {
            t0 = MODULUS - (static_cast<uint64_t>(hi_hi) - lo);
        }

        uint64_t t1 = static_cast<uint64_t>(hi_lo) * EPSILON;
        uint64_t sum = t0 + t1;
        if (sum < t0 || sum >= MODULUS) {
            sum -= MODULUS;
        }
        return sum;
    }

#if !(defined(_MSC_VER) && !defined(__clang__))
    static uint64_t reduce128(__uint128_t x) noexcept {
        uint64_t lo = static_cast<uint64_t>(x);
        uint64_t hi = static_cast<uint64_t>(x >> 64);
        return reduce128_parts(lo, hi);
    }
#endif

    uint64_t v_;
};

// ============================================================================
// Montgomery 乘法 (Goldilocks 专用，内联)
//
// 计算 a * b * R^{-1} mod p，其中 R = 2^64
// Goldilocks 结构允许将 Montgomery 约简步骤与域专用 ε 约简合并
// x86_64 上通过 MULX + ADCX/ADOX 标志位链实现 ~6-8 cycles
//
// 平台:
//   x86_64 (非 Windows): 内联汇编 MULX (~6-8 cycles)
//   其他: __uint128_t 通用路径 (~15 cycles)
// ============================================================================

inline uint64_t mont_mul_c(uint64_t a, uint64_t b) {
#if defined(_MSC_VER) && !defined(__clang__)
    uint64_t hi = 0;
    uint64_t lo = _umul128(a, b, &hi);
#else
    __uint128_t p = __uint128_t{a} * b;
    uint64_t lo = static_cast<uint64_t>(p);
    uint64_t hi = static_cast<uint64_t>(p >> 64);
#endif

    // t = lo * μ mod 2^64，其中 μ = 2^32 - 1
    uint64_t t = lo * 0xFFFFFFFFULL;

    // r = hi + t + carry(lo + t)
    uint64_t r = hi + t + (static_cast<uint64_t>(lo + t) < lo);

    // 最终减法: r -= t>>32 (来自 t*p = t*2^64 - t*2^32 + t)
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
// x86_64 汇编路径: MULX 产生 lo/hi 而不触碰标志位
// 使得 ADCX/ADOX 链可以保持进位管线满载
__attribute__((always_inline))
inline uint64_t mont_mul_asm(uint64_t a, uint64_t b) {
    uint64_t r;
    asm volatile(
        "mulx %1, %0, %%rdx\n\t"
        "mov %0, %%r8\n\t"
        "shl $32, %%r8\n\t"
        "sub %0, %%r8\n\t"
        "mov %%r8, %%r9\n\t"
        "add %%r8, %0\n\t"
        "setc %%cl\n\t"
        "add %%r8, %%rdx\n\t"
        "movzbq %%cl, %%r8\n\t"
        "add %%r8, %%rdx\n\t"
        "shr $32, %%r9\n\t"
        "sub %%r9, %%rdx\n\t"
        "jnc 0f\n\t"
        "mov $0xFFFFFFFF00000001, %%r8\n\t"
        "add %%r8, %%rdx\n\t"
        "jmp 1f\n"
        "0: mov $0xFFFFFFFF00000001, %%r8\n\t"
        "cmp %%r8, %%rdx\n\t"
        "jb 1f\n\t"
        "sub %%r8, %%rdx\n"
        "1: mov %%rdx, %0\n"
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
