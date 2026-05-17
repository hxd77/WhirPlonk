#pragma once

// 对应 WHIR 中的 src/utils.rs 的核心子集。
// 跳过的项: zip_strict (C++ 用 size assert + range-for 等价), test_serde (无 serde),
// ensure! 宏 (用 if + throw 等价)。
//
//   workload_size<T>()             —— 单线程目标 workload, 与 Rust 跨平台分支对齐
//   base_decomposition(value, base, n_bits) —— big-endian base 进制分解
//   expand_randomness<F>(base, n)  —— (1, base, base^2, ..., base^(n-1))

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace whir {

//与 Rust 一致的平台相关 cache size 选择。
//C++ 端没有 #cfg, 用预处理宏判断目标平台。
//在编译时，根据不同的CPU架构和操作系统,计算出CPU高速缓存(L1)中能够容纳多少个类型为T的数据元素
template <typename T>
constexpr std::size_t workload_size() noexcept {
#if defined(__APPLE__) && defined(__aarch64__) //苹果ARM架构
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 17; //128KB Apple Silicon
#elif defined(__aarch64__) && (defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__))
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 16; //64KB ARM mobile/server
#elif defined(__x86_64__) || defined(_M_X64)
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 15; //32KB x86-64
#else
    constexpr std::size_t CACHE_SIZE = std::size_t{1} << 15; //32KB default
#endif
    return CACHE_SIZE / sizeof(T);
}

//把一个无符号数value转换成指定进制(base)表示形式，并将结果每一位提取出来,存入一个固定长度(n_bits)数组中,采用大端序存储
//value = v[0] * base^(n_bits-1) + v[1] * base^(n_bits-2) + ... + v[n_bits-1].
//value >= base^n_bits 时, 实际是 value mod base^n_bits 的分解。
inline std::vector<std::uint8_t> base_decomposition(
    std::size_t value, std::uint8_t base, std::size_t n_bits) //n_bits代表指定输出数组的长度
{
    assert(base > 1 && "base must be at least 2");
    std::vector<std::uint8_t> result(n_bits, 0); //创建n_bits数组，并将所有元素赋值为0
    for (std::size_t i = n_bits; i-- > 0;) { //倒序循环
        result[i] = static_cast<std::uint8_t>(value % base);//求余数得到最低位的值
        value /= base; //除以进制数
    }
    return result; //返回一个转换后每一位数字的数组
}

//(1, base, base^2, ..., base^(len-1))。
//与 algebra/utilities.hpp 中的 geometric_sequence 行为一致。
template <typename F>
std::vector<F> expand_randomness(F base, std::size_t len) {
    std::vector<F> out;
    out.reserve(len); //提前分配len长度数组
    F acc = F::one();
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(acc);
        acc = acc * base;
    }
    return out;
}

} // namespace whir
