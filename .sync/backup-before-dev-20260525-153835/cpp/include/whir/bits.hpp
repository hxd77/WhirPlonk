#pragma once

// ============================================================================
// bits.hpp — 安全参数的位宽包装
//
// 用 double 封装位级度量 (security_level, pow_bits), 支持小数位宽。
// 提供有限值断言和三路比较运算符, 与 Rust f64-based Bits 类型兼容。
//
// 设计理由:
//   使用 double 允许小数位宽 (如 128.5 bits), 构造时断言有限性以尽早拦截 NaN/Inf。
//
// 对应 Rust: src/bits.rs
// ============================================================================

#include <cassert>
#include <cmath>
#include <compare>
#include <iosfwd>
#include <ostream>

namespace whir {

class Bits {
public:
    constexpr Bits() noexcept : v_(0.0) {}

    // 构造时断言有限性: NaN/Inf 会无声地污染下游安全参数计算 (阈值、折叠因子)
    explicit Bits(double bits) : v_(bits) {
        assert(std::isfinite(bits) && "Bits requires a finite value");
    }

    constexpr double value() const noexcept { return v_; }
    constexpr explicit operator double() const noexcept { return v_; }
    constexpr bool is_zero() const noexcept { return v_ == 0.0; }

    // 构造器保证有限性, <=> 运算符良定义 (对标 Rust PartialOrd + Ord)
    friend constexpr auto operator<=>(const Bits& a, const Bits& b) noexcept = default;
    friend constexpr bool operator==(const Bits& a, const Bits& b) noexcept = default;

    friend std::ostream& operator<<(std::ostream& os, const Bits& b) {
        return os << b.v_;
    }

private:
    double v_;
};

} // namespace whir
