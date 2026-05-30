#pragma once

// ============================================================================
// utils.hpp — 平台感知缓存适配与数值分解工具
//
// 提供:
//   workload_size<T>()                  — 每线程 L1 适配元素数
//   base_decomposition(value, base, n)  — 大端进制分解
//   expand_randomness<F>(base, n)       — 几何序列 (1, base, ..., base^{n-1})
//
// 对应 Rust: src/utils.rs
// ============================================================================

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace whir {

// 返回单个 L1 缓存可容纳的 T 类型元素数, 用作单线程 NTT 和折叠的目标工作集,
// 以最小化递归分解时的 L2/L3 缓存压力。
//
// 各平台 L1 缓存大小:
//   Apple Silicon (aarch64): 128 KB
//   ARM mobile/server:       64 KB
//   x86-64:                  32 KB
template <typename T>
constexpr std::size_t workload_size() noexcept {
#if defined(__APPLE__) && defined(__aarch64__)
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 17;
#elif defined(__aarch64__) && (defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__))
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 16;
#elif defined(__x86_64__) || defined(_M_X64)
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 15;
#else
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 15;
#endif
    return CACHE_SIZE / sizeof(T);
}

// 大端进制分解:
//   value = result[0] * base^(n-1) + result[1] * base^(n-2) + ... + result[n-1]
//
// 若 value >= base^n, 则隐式取模 (value mod base^n)。
// 用于 Fiat-Shamir 挑战索引生成。
inline std::vector<std::uint8_t> base_decomposition(
    std::size_t value, std::uint8_t base, std::size_t n_bits)
{
    assert(base > 1 && "base must be at least 2");
    std::vector<std::uint8_t> result(n_bits, 0);
    for (std::size_t i = n_bits; i-- > 0;) {
        result[i] = static_cast<std::uint8_t>(value % base);
        value /= base;
    }
    return result;
}

// 几何序列: (1, base, base^2, ..., base^{len-1})。
// 等价于 algebra/utilities.hpp::geometric_sequence, 但操作泛型域类型 F,
// 无需引入代数头文件。
template <typename F>
std::vector<F> expand_randomness(F base, std::size_t len) {
    std::vector<F> out;
    out.reserve(len);
    F acc = F::one();
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(acc);
        acc = acc * base;
    }
    return out;
}

} // namespace whir
