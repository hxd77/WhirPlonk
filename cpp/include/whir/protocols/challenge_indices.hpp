#pragma once

// ============================================================================
// challenge_indices.hpp — Fiat-Shamir 挑战索引生成
//
// 从 transcript 熵为 IRS 承诺域内查询生成随机叶子索引。验证者从
// Fiat-Shamir transcript 挤压随机字节，然后通过拒绝采样（模约减）
// 映射到 [0, num_leaves) 范围内的索引。
//
// 算法（与 Rust challenge_indices() 一致）:
//   count == 0        -> 空
//   num_leaves == 1   -> dedup ? [0] : count 个 0 的副本
//   其他情况:
//     size_bytes = ceil(log2(num_leaves) / 8)
//     熵长度 = count * size_bytes
//     每段 size_bytes 字节按大端解码，然后 mod num_leaves
//     若 deduplicate: sort + unique
//
// @pre num_leaves 必须是 2 的幂次（已断言）。
//
// 对应 Rust 文件: src/protocols/challenge_indices.rs
// ============================================================================

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "../transcript/transcript.hpp"

namespace whir::protocols::challenge_indices {

/// 检查 n 是否为 2 的幂次。
inline bool is_power_of_two(std::size_t n) noexcept {
    return n != 0 && (n & (n - 1)) == 0;
}

/// ceil(log2(n))，其中 n >= 1 且为 2 的幂次。
/// 等价于二进制表示中尾随零的个数。
inline std::size_t log2_pow2(std::size_t n) noexcept {
    assert(n >= 1 && (n & (n - 1)) == 0);
    std::size_t k = 0;
    while ((std::size_t{1} << k) < n) ++k;
    return k;
}

/// 将原始熵字节串转换为叶子索引向量。
///
/// 每段 @p size_bytes 字节按大端解码为整数，然后对 @p num_leaves 取模。
/// 可选去重。
///
/// @pre entropy.size() == count * ceil(log2(num_leaves) / 8)
/// @pre num_leaves 是 2 的幂次
inline std::vector<std::size_t> indices_from_entropy(
    std::span<const std::uint8_t> entropy,
    std::size_t num_leaves,
    std::size_t count,
    bool deduplicate)
{
    if (count == 0) return {};
    assert(is_power_of_two(num_leaves) && "num_leaves must be a power of two");
    if (num_leaves == 1) {
        if (deduplicate) return {0};
        return std::vector<std::size_t>(count, 0);
    }

    // 每个索引的字节数: ceil(log2(num_leaves) / 8)
    const std::size_t size_bytes = (log2_pow2(num_leaves) + 7) / 8;
    assert(entropy.size() == count * size_bytes && "entropy length mismatch");

    std::vector<std::size_t> indices;
    indices.reserve(count);

    // 逐段按大端解码，然后 mod num_leaves
    for (std::size_t i = 0; i < count; ++i) {
        std::size_t acc = 0;
        for (std::size_t b = 0; b < size_bytes; ++b) {
            acc = (acc << 8) | static_cast<std::size_t>(entropy[i * size_bytes + b]);
        }
        indices.push_back(acc % num_leaves);
    }

    if (deduplicate) {
        std::sort(indices.begin(), indices.end());
        indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
    }
    return indices;
}

/// Transcript 包装器: 从 Fiat-Shamir transcript 挤压熵字节，
/// 然后通过 indices_from_entropy() 转换为挑战索引。
///
/// @tparam Transcript  必须支持 verifier_message<uint8_t>()
template <typename Transcript>
std::vector<std::size_t> challenge_indices(
    Transcript& transcript,
    std::size_t num_leaves,
    std::size_t count,
    bool deduplicate)
{
    if (count == 0) return {};
    assert(is_power_of_two(num_leaves));
    if (num_leaves == 1) {
        if (deduplicate) return {0};
        return std::vector<std::size_t>(count, 0);
    }

    const std::size_t size_bytes = (log2_pow2(num_leaves) + 7) / 8;
    std::size_t total_bytes = count * size_bytes;

    // 逐字节从 transcript 挤压
    std::vector<std::uint8_t> entropy(total_bytes);
    for (auto& b : entropy)
        b = transcript.template verifier_message<std::uint8_t>();

    return indices_from_entropy(entropy, num_leaves, count, deduplicate);
}

} // namespace whir::protocols::challenge_indices
