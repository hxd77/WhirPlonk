#pragma once

#include "goldilocks.hpp"

namespace whir::algebra {

// Cubic extension Fp3 = Fp[X] / (X^3 - 2) over Goldilocks.
// Element layout: c0 + c1*X + c2*X^2.
// Matches ark-ff F3Config64 from src/algebra/fields.rs (NONRESIDUE = 2).
//
// Frobenius coefficients (from ark-ff FROBENIUS_COEFF_FP3_C{1,2}):
//   omega    = 2^((p-1)/3) mod p = 4294967295           = 2^32 - 1
//   omega^2                      = 18446744065119617025 = p - 2^32
class GoldilocksExt3 {
public:
    using BaseField = Goldilocks; //基域别名，供 Embedding / Basefield 模板使用
    static constexpr uint64_t NONRESIDUE = 2;
    static constexpr double field_size_bits = 192.0;
    static constexpr uint64_t OMEGA_U64    = 4294967295ULL;
    static constexpr uint64_t OMEGA_SQ_U64 = 18446744065119617025ULL;

    constexpr GoldilocksExt3() noexcept = default;
    constexpr GoldilocksExt3(Goldilocks c0, Goldilocks c1, Goldilocks c2) noexcept
        : c0_(c0), c1_(c1), c2_(c2) {}

    static constexpr GoldilocksExt3 zero() noexcept {
        return {};
    }
    static constexpr GoldilocksExt3 one() noexcept {
        return {Goldilocks::one(), Goldilocks::zero(), Goldilocks::zero()};
    }

    template <typename Rng>
    static GoldilocksExt3 random(Rng& rng) {
        return {Goldilocks::random(rng), Goldilocks::random(rng), Goldilocks::random(rng)};
    }
    static constexpr GoldilocksExt3 from_base(Goldilocks a) noexcept {
        return {a, Goldilocks::zero(), Goldilocks::zero()};
    }
    static constexpr GoldilocksExt3 from_u64(uint64_t v) noexcept {
        return from_base(Goldilocks::from_u64(v));
    }

    constexpr Goldilocks c0() const noexcept { return c0_; }
    constexpr Goldilocks c1() const noexcept { return c1_; }
    constexpr Goldilocks c2() const noexcept { return c2_; }

    friend constexpr bool operator==(const GoldilocksExt3& a, const GoldilocksExt3& b) noexcept {
        return a.c0_ == b.c0_ && a.c1_ == b.c1_ && a.c2_ == b.c2_;
    }
    friend constexpr bool operator!=(const GoldilocksExt3& a, const GoldilocksExt3& b) noexcept {
        return !(a == b);
    }

    friend constexpr GoldilocksExt3 operator+(const GoldilocksExt3& a, const GoldilocksExt3& b) noexcept {
        return {a.c0_ + b.c0_, a.c1_ + b.c1_, a.c2_ + b.c2_};
    }
    friend constexpr GoldilocksExt3 operator-(const GoldilocksExt3& a) noexcept {
        return {-a.c0_, -a.c1_, -a.c2_};
    }
    friend constexpr GoldilocksExt3 operator-(const GoldilocksExt3& a, const GoldilocksExt3& b) noexcept {
        return {a.c0_ - b.c0_, a.c1_ - b.c1_, a.c2_ - b.c2_};
    }

    // (a0 + a1 X + a2 X^2)(b0 + b1 X + b2 X^2), reduced by X^3 = NR:
    //   c0 = a0 b0 + NR (a1 b2 + a2 b1)
    //   c1 = a0 b1 + a1 b0 + NR a2 b2
    //   c2 = a0 b2 + a1 b1 + a2 b0
    friend GoldilocksExt3 operator*(const GoldilocksExt3& a, const GoldilocksExt3& b) noexcept {
        Goldilocks nr = Goldilocks::from_u64(NONRESIDUE);
        Goldilocks out0 = a.c0_ * b.c0_ + nr * (a.c1_ * b.c2_ + a.c2_ * b.c1_);
        Goldilocks out1 = a.c0_ * b.c1_ + a.c1_ * b.c0_ + nr * (a.c2_ * b.c2_);
        Goldilocks out2 = a.c0_ * b.c2_ + a.c1_ * b.c1_ + a.c2_ * b.c0_;
        return {out0, out1, out2};
    }

    GoldilocksExt3& operator+=(const GoldilocksExt3& o) noexcept { *this = *this + o; return *this; }
    GoldilocksExt3& operator-=(const GoldilocksExt3& o) noexcept { *this = *this - o; return *this; }
    GoldilocksExt3& operator*=(const GoldilocksExt3& o) noexcept { *this = *this * o; return *this; }

    GoldilocksExt3 square() const noexcept { return *this * *this; }

    GoldilocksExt3 pow(uint64_t exp) const noexcept {
        GoldilocksExt3 result = one();
        GoldilocksExt3 base = *this;
        while (exp > 0) {
            if (exp & 1u) result *= base;
            exp >>= 1;
            if (exp > 0) base = base.square();
        }
        return result;
    }

    // Explicit Fp3 inverse. Let z = c0 + c1 X + c2 X^2 with X^3 = NR.
    //   A = c0^2 - NR * c1 * c2
    //   B = NR * c2^2 - c0 * c1
    //   C = c1^2 - c0 * c2
    //   N = c0 * A + NR * (c2 * B + c1 * C)       [lives in Fp, = norm of z]
    //   z^{-1} = (A, B, C) / N
    GoldilocksExt3 inverse() const noexcept {
        Goldilocks nr = Goldilocks::from_u64(NONRESIDUE);
        Goldilocks A = c0_ * c0_ - nr * (c1_ * c2_);
        Goldilocks B = nr * (c2_ * c2_) - c0_ * c1_;
        Goldilocks C = c1_ * c1_ - c0_ * c2_;
        Goldilocks N = c0_ * A + nr * (c2_ * B + c1_ * C);
        Goldilocks N_inv = N.inverse();
        return {A * N_inv, B * N_inv, C * N_inv};
    }

    // Frobenius^k acts as: (c0, c1, c2) -> (c0, c1 * omega^k, c2 * omega^(2k))
    // with omega^3 = 1. Matches ark-ff FROBENIUS_COEFF_FP3_C{1,2}.
    GoldilocksExt3 frobenius_map(uint64_t k) const noexcept {
        k %= 3;
        if (k == 0) return *this;
        Goldilocks w  = Goldilocks::from_u64(OMEGA_U64);
        Goldilocks w2 = Goldilocks::from_u64(OMEGA_SQ_U64);
        if (k == 1) return {c0_, c1_ * w,  c2_ * w2};
        // k == 2
        return {c0_, c1_ * w2, c2_ * w};
    }

private:
    Goldilocks c0_;
    Goldilocks c1_;
    Goldilocks c2_;
};

} // namespace whir::algebra
