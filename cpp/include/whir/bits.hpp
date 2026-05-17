#pragma once

// 对应 WHIR 中的 src/bits.rs。
// f64 包装器, 用来表示比特单位的浮点数 (security level / pow_bits 等数据)。
// 提供 finite 检查 + 全序比较。
//
// Rust 端的 Hash / Serialize 实现 C++ 没有对应需要, 这里不引入;
// 哈希用裸 f64 比对位串, 等价于 Rust Hasher 实现。

#include <cassert>
#include <cmath>
#include <compare>
#include <iosfwd>
#include <ostream>

namespace whir {

//一个以Bit为单位表示安全参数的数值包装类型
//用Bits表示安全强度位数和PoW难度位数，例如Bits(100.0)表示100位安全强度
class Bits {
public:
    constexpr Bits() noexcept : v_(0.0) {} //默认构造

    explicit Bits(double bits) : v_(bits) {
        assert(std::isfinite(bits) && "Bits requires a finite value"); //检查isfinite是不是一个有限的数字
    } //显式构造,NaN/Inf会触发aasert 

    constexpr double value() const noexcept { return v_; } //取内部值
    constexpr explicit operator double() const noexcept { return v_; }//重载double

    constexpr bool is_zero() const noexcept { return v_ == 0.0; } //安全参数是否为0

    //Rust 端 PartialOrd::partial_cmp + Ord::cmp 都用 partial_cmp().unwrap()。
    //这里直接用三路比较, 遇到 NaN 会 unordered, 与 Rust unwrap() 行为差一点 (Rust 会 panic)。
    //实际上构造函数已经禁止 NaN/Inf, 所以三路比较等价于全序。
    
    //重载大于、小于和等于
    friend constexpr auto operator<=>(const Bits& a, const Bits& b) noexcept = default;
    
    //重载等于
    friend constexpr bool operator==(const Bits& a, const Bits& b) noexcept = default;

    //重载打印输出
    friend std::ostream& operator<<(std::ostream& os, const Bits& b) {
        return os << b.v_;
    }
    
private:
    double v_;
};

} // namespace whir
