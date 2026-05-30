#pragma once

// ============================================================================
// goldilocks_ext2.hpp — 二次扩域 Fp2 = Fp[X] / (X^2 - 7)
//
// 不可约多项式: X^2 - 7，其中 7 是模 p 的二次非剩余。
// 由 Euler 判据: 7^{(p-1)/2} ≡ -1 (mod p)，故 X^2 = 7 在 Fp 中无解，
// 从而保证不可约性。
//
// 元素布局: c0 + c1 * X，其中 c0, c1 ∈ Fp。
// 对应 ark-ff F2Config64 (NONRESIDUE = 7)。
//
// 求逆: (c0 + c1 X)^{-1} = (c0 - c1 X) / (c0^2 - 7 * c1^2)
//   norm = c0^2 - NR * c1^2（属于 Fp，对非零输入恒不为零）
//
// Frobenius: (c0 + c1 X)^p = c0 - c1 X（共轭）
//   因为 X^p = X * 7^{(p-1)/2} = -X（Euler 判据）。
//   Frobenius^k: k 为偶数时恒等，k 为奇数时取共轭。
// ============================================================================

#include "goldilocks.hpp"

namespace whir::algebra {

class GoldilocksExt2 {
public:
    using BaseField = Goldilocks;
    static constexpr uint64_t NONRESIDUE = 7;
    static constexpr double field_size_bits = 128.0;

    constexpr GoldilocksExt2() noexcept = default;
    constexpr GoldilocksExt2(Goldilocks c0, Goldilocks c1) noexcept
        : c0_(c0), c1_(c1) {}

    static constexpr GoldilocksExt2 zero() noexcept {
        return {Goldilocks::zero(), Goldilocks::zero()};
    }
    static constexpr GoldilocksExt2 one() noexcept {
        return {Goldilocks::one(), Goldilocks::zero()};
    }

    template <typename Rng>
    static GoldilocksExt2 random(Rng& rng) {
        return {Goldilocks::random(rng), Goldilocks::random(rng)};
    }
    static constexpr GoldilocksExt2 from_base(Goldilocks a) noexcept {
        return {a, Goldilocks::zero()};
    }
    static constexpr GoldilocksExt2 from_u64(uint64_t v) noexcept {
        return from_base(Goldilocks::from_u64(v));
    }

    constexpr Goldilocks c0() const noexcept { return c0_; }
    constexpr Goldilocks c1() const noexcept { return c1_; }

    friend constexpr bool operator==(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept {
        return a.c0_ == b.c0_ && a.c1_ == b.c1_;
    }
    friend constexpr bool operator!=(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept {
        return !(a == b);
    }

    friend constexpr GoldilocksExt2 operator+(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept {
        return {a.c0_ + b.c0_, a.c1_ + b.c1_};
    }
    friend constexpr GoldilocksExt2 operator-(const GoldilocksExt2& a) noexcept {
        return {-a.c0_, -a.c1_};
    }
    friend constexpr GoldilocksExt2 operator-(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept {
        return {a.c0_ - b.c0_, a.c1_ - b.c1_};
    }

    // Fp2 中的乘法。使用 Karatsuba 形式将 4 次基域乘法降为 3 次:
    //   v0 = a0 b0, v1 = a1 b1
    //   c0 = v0 + NR * v1
    //   c1 = (a0+a1)(b0+b1) - v0 - v1
    friend GoldilocksExt2 operator*(const GoldilocksExt2& a, const GoldilocksExt2& b) noexcept {
        Goldilocks nr = Goldilocks::from_u64(NONRESIDUE);
        Goldilocks v0 = a.c0_ * b.c0_;
        Goldilocks v1 = a.c1_ * b.c1_;
        Goldilocks out0 = v0 + nr * v1;
        Goldilocks out1 = (a.c0_ + a.c1_) * (b.c0_ + b.c1_) - v0 - v1;
        return {out0, out1};
    }

    GoldilocksExt2& operator+=(const GoldilocksExt2& o) noexcept { *this = *this + o; return *this; }
    GoldilocksExt2& operator-=(const GoldilocksExt2& o) noexcept { *this = *this - o; return *this; }
    GoldilocksExt2& operator*=(const GoldilocksExt2& o) noexcept { *this = *this * o; return *this; }

    GoldilocksExt2 square() const noexcept { return *this * *this; }

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

    // 通过共轭求逆:
    //   (c0 + c1 X)^{-1} = conj / norm
    //   其中 conj = c0 - c1 X，norm = c0^2 - NR * c1^2 ∈ Fp。
    GoldilocksExt2 inverse() const noexcept {
        Goldilocks nr = Goldilocks::from_u64(NONRESIDUE);
        Goldilocks norm = c0_ * c0_ - nr * (c1_ * c1_);
        Goldilocks norm_inv = norm.inverse();
        return {c0_ * norm_inv, -(c1_ * norm_inv)};
    }

    // Frobenius 自同态: x |-> x^{p^k}
    // 在 Fp2 中，k 为奇数时退化为共轭，k 为偶数时退化为恒等。
    // 推导（Freshman's Dream + Euler 判据）:
    //   (c0 + c1 X)^p = c0^p + c1^p X^p = c0 + c1 * (-X) = c0 - c1 X
    GoldilocksExt2 frobenius_map(uint64_t k) const noexcept {
        if ((k & 1u) == 0) return *this;
        return {c0_, -c1_};
    }

private:
    Goldilocks c0_;
    Goldilocks c1_;
};

} // namespace whir::algebra
