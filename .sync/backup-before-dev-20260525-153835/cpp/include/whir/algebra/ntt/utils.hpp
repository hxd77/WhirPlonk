#pragma once

// ============================================================================
// utils.hpp — NTT 分解所需的数论工具函数
//
// 提供 GCD、LCM、尾零计数、2 的幂判断，以及 √N Cooley-Tukey 分解所用的
// sqrt_factor 函数。
//
// sqrt_factor(n) 返回 n 的最大因子 f，满足 f ≤ √n，其中 n = 2^k × base，
// base ∈ {1, 3, 9}。这是 Goldilocks 域 NTT 阶数的标准形式
//（如 2^32、2^32 × 3）。两个因子 n1 = f 和 n2 = n/f 经平衡处理，
// 以最小化两层子 NTT 的缓存未命中。
//
// 对应 Rust 源文件：src/algebra/ntt/utils.rs
// ============================================================================

#include <cassert>
#include <cstddef>

namespace whir::algebra::ntt {

// 欧几里得最大公约数。gcd(0, 0) = 0（与 Rust 行为一致）。
constexpr std::size_t gcd(std::size_t a, std::size_t b) noexcept {
    while (b != 0) {
        const std::size_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

// 最小公倍数。lcm(0, x) = 0。
constexpr std::size_t lcm(std::size_t a, std::size_t b) noexcept {
    return a * (b / gcd(a, b));
}

// 计算整数n的二进制表示中尾部零位的个数。n == 0 时返回 sizeof(size_t) × 8。
constexpr unsigned trailing_zeros(std::size_t n) noexcept {
    if (n == 0) return sizeof(std::size_t) * 8;
    unsigned count = 0;
    while ((n & 1u) == 0u) {
        ++count;
        n >>= 1;
    }
    return count;
}

// 判断是不是2的幂
constexpr bool is_power_of_two(std::size_t n) noexcept {
    return n != 0 && (n & (n - 1)) == 0;
}

// 返回 n 的最大因子 f，满足 f ≤ sqrt(n)。
//
// 前置条件：n = 2^k × base，其中 base ∈ {1, 3, 9}。
//
// f 的选择平衡了两个子 NTT 的规模（f 和 n/f），使 √N Cooley-Tukey 递归
// 在每一层的工作量大致相等。
//
// 按 base 分类讨论：
//   base=1: n = 2^k       → f = 2^(k/2)
//   base=3: n = 2^k × 3   → k 为偶数时将因子 3 分配给较大半部分
//   base=9: n = 2^k × 9   → 各半部分各分配一个因子 3（√9 = 3）
constexpr std::size_t sqrt_factor(std::size_t n) {
    const unsigned twos = trailing_zeros(n); //表示n中有2^twos这个因子
    const std::size_t base = n >> twos; 
    //假设n=48=2^4*3
    //twos=4
    //base=48>>4=3
    //n=2^twos*base

    switch (base) {
        case 1: //n=2^k
            return std::size_t{1} << (twos / 2); //,所以sqrt(n)=2^(k/2)
        case 3: //n=2^k*3
            if (twos == 0) { 
                return 1; //n=3,sqrt(3)约等于1.732小于这个的最大因子是1
            }
            if (twos % 2 == 0) { //n=2^4*3=48
                // 偶数个 2 的幂：将因子 3 分配给较大半部分
                return std::size_t{3} << ((twos - 1) / 2); //sqrt(48)约等于6.928,48因子有1, 2, 3, 4, 6, 8, 12, 16, 24, 48,不超过的最大因子是6
            }
            // 奇数个 2 的幂：因子 3 留在较小半部分
            return std::size_t{2} << (twos / 2);
        case 9: //n=2^k*9
            if (twos == 1) {
                return 3;  // n=18 → 3×6，3 ≤ √18
            }
            if (twos % 2 == 0) { //n=2^4*9=144
                // 各半部分各分配一个因子,因为9=3*3
                return std::size_t{3} << (twos / 2); //sqrt(144)=12, 3<<(4/2)=3<<2=12
            }
            return std::size_t{4} << (twos / 2);
        default:
            assert(!"sqrt_factor: n is not in form 2^k * {1, 3, 9}");
            return 0;
    }
}

} // namespace whir::algebra::ntt
