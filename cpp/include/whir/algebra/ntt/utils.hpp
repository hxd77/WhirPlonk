#pragma once

// =============================================================================
// utils.hpp — NTT 相关数学工具函数。
// 对应 WHIR 中的 src/algebra/ntt/utils.rs。
//
// 提供:
//   gcd(a, b)           — 最大公约数 (欧几里得算法)
//   lcm(a, b)           — 最小公倍数
//   trailing_zeros(n)   — 二进制末尾零位数 (等价 Rust trailing_zeros)
//   is_power_of_two(n)  — 判断是否为 2 的幂
//   sqrt_factor(n)      — n = 2^k * {1,3,9} 时, 返回 ≤√n 的最大因子
//
// sqrt_factor 是 √N Cooley-Tukey NTT 分解的核心: 把 size 分解为 n1 * n2,
// n1 = sqrt_factor(size), n2 = size / n1, 两者尽量接近以最小化缓存失效。
// =============================================================================

#include <cassert>
#include <cstddef>

namespace whir::algebra::ntt {

// ---------------------------------------------------------------------------
// gcd(a, b) — 欧几里得最大公约数。
// 输入: 两个 size_t 非负整数
// 输出: 最大公约数; gcd(0, 0) = 0 (与 Rust 行为一致)
// ---------------------------------------------------------------------------
constexpr std::size_t gcd(std::size_t a, std::size_t b) noexcept {
    while (b != 0) {
        const std::size_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

// ---------------------------------------------------------------------------
// lcm(a, b) — 最小公倍数。
// 输入: 两个 size_t 非负整数
// 输出: 最小公倍数; lcm(0, x) = 0 (a/gcd(a,b) 在 gcd=0 时是 0/0 即 0)
// 注意: gcd(0,0)=0 时 a/gcd 为 0/0 (UB), 但 lcm(0,0) 语义上 = 0, 此处与
//       Rust 行为一致, 调用方不应传两个 0。
// ---------------------------------------------------------------------------
constexpr std::size_t lcm(std::size_t a, std::size_t b) noexcept {
    return a * (b / gcd(a, b));
}

// ---------------------------------------------------------------------------
// trailing_zeros(n) — 二进制末尾连续零的个数。
// 输入: n — 任意 size_t 值
// 输出: n 的二进制表示中最低位 1 右侧的零的个数; n==0 时返回 sizeof(size_t)*8
// 等价于 Rust 的 trailing_zeros() 内建函数。
// ---------------------------------------------------------------------------
constexpr unsigned trailing_zeros(std::size_t n) noexcept {
    if (n == 0) return sizeof(std::size_t) * 8;
    unsigned count = 0;
    while ((n & 1u) == 0u) {
        ++count;
        n >>= 1;
    }
    return count;
}

// ---------------------------------------------------------------------------
// is_power_of_two(n) — 判断 n 是否为 2 的幂。
// 输入: n — 任意 size_t 值
// 输出: true 当且仅当 n > 0 且 n 的二进制表示中只有 1 个 1
// ---------------------------------------------------------------------------
constexpr bool is_power_of_two(std::size_t n) noexcept {
    return n != 0 && (n & (n - 1)) == 0;
}

// ---------------------------------------------------------------------------
// sqrt_factor(n) — 返回 ≤√n 的最大因子, 用于 √N Cooley-Tukey 分解。
//
// 假设 n = 2^twos * base, 其中 base ∈ {1, 3, 9}。
// 这是 Goldilocks 域 NTT 的典型 order 形式 (2^32 或 2^32 * 3 等)。
//
// 输入: n — 满足上述形式的正整数
// 输出: n 的一个因子 f, 满足 f ≤ √n, 且 f 尽可能大
//       使得 n1 = sqrt_factor(n) 与 n2 = n / n1 尽量接近,
//       从而 √N 风格 Cooley-Tukey 的两次子 NTT 工作量均衡。
//
// 算法 (按 base 分类):
//   base=1: n 是 2 的幂 → 返回 2^(twos/2)
//   base=3: 分 twos 奇偶, 尽量把因子 3 分给较大的那半
//   base=9: 分 twos 奇偶和 twos==1 特判
// ---------------------------------------------------------------------------
constexpr std::size_t sqrt_factor(std::size_t n) {
    const unsigned twos = trailing_zeros(n);
    const std::size_t base = n >> twos;

    switch (base) {
        case 1:
            // n = 2^twos, 最大 ≤√n 的因子是 2^(twos/2)
            return std::size_t{1} << (twos / 2);
        case 3:
            // n = 2^twos * 3
            if (twos == 0) {
                return 1;
            }
            if (twos % 2 == 0) {
                // 2 的幂为偶数, 因子 3 分给稍大的半: 2^((twos-1)/2) * 3
                return std::size_t{3} << ((twos - 1) / 2);
            }
            // 2 的幂为奇数, 3 留在较小半: 2^(twos/2) * 2
            return std::size_t{2} << (twos / 2);
        case 9:
            // n = 2^twos * 9
            if (twos == 1) {
                return 3;  // n=18 → 3*6, 3≤√18
            }
            if (twos % 2 == 0) {
                // 3 是 9 的平方根, 给每半各一个 3
                return std::size_t{3} << (twos / 2);
            }
            // 9 = 3*3, 把因子在两半间不平分
            return std::size_t{4} << (twos / 2);
        default:
            assert(!"sqrt_factor: n is not in form 2^k * {1, 3, 9}");
            return 0;
    }
}

} // namespace whir::algebra::ntt
