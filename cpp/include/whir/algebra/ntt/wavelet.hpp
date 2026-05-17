#pragma once

// =============================================================================
// wavelet.hpp — 快速小波变换 (Fast Wavelet Transform)。
// 对应 WHIR 中的 src/algebra/ntt/wavelet.rs。
//
// 小波变换对每对 (a, b) 应用线性变换核:
//   前向: [a'] = [1  0] [a]  即 a'=a, b'=a+b
//         [b']   [1  1] [b]
//   反向: [a'] = [1  0] [a]  即 a'=a, b'=b-a
//         [b']   [-1 1] [b]
//
// 输入长度必须是 2 的幂。批量版本对每段长度为 size 的子块独立做变换。
//
// 提供:
//   wavelet_transform(values)                    — 整段前向小波变换
//   wavelet_transform_batch(values, size)        — 批量前向, 每块 size 长
//   inverse_wavelet_transform(values)            — 整段反向小波变换
//   inverse_wavelet_transform_batch(values, size)— 批量反向
//
// 小波变换在 WHIR 协议中的用途:
//   作为 NTT 的替代方案, 小波基可以简化折叠 (folding) 操作。
//   与 NTT 类似, 它是一个可逆线性变换, 把系数表示转为求值表示。
// =============================================================================

#include "transpose.hpp"
#include "utils.hpp"

#include <cassert>
#include <cstddef>
#include <span>

namespace whir::algebra::ntt {

template <typename F>
void wavelet_transform_batch(std::span<F> values, std::size_t size);

template <typename F>
void inverse_wavelet_transform_batch(std::span<F> values, std::size_t size);

// ---------------------------------------------------------------------------
// wavelet_transform(values) — 对整个数组做前向小波变换。
// 输入: values — 长度必须是 2 的幂的域元素数组
// 效果: 原地变换, values[i] 被替换为其小波变换结果
// 等价于 wavelet_transform_batch(values, values.size())
// ---------------------------------------------------------------------------
template <typename F>
void wavelet_transform(std::span<F> values) {
    assert(is_power_of_two(values.size()));
    wavelet_transform_batch<F>(values, values.size());
}

// ---------------------------------------------------------------------------
// inverse_wavelet_transform(values) — 对整个数组做反向小波变换。
// 输入: values — 长度必须是 2 的幂的域元素数组 (已做过前向变换)
// 效果: 原地恢复为原始值
// 等价于 inverse_wavelet_transform_batch(values, values.size())
// ---------------------------------------------------------------------------
template <typename F>
void inverse_wavelet_transform(std::span<F> values) {
    assert(is_power_of_two(values.size()));
    inverse_wavelet_transform_batch<F>(values, values.size());
}

// ---------------------------------------------------------------------------
// inverse_wavelet_transform_batch(values, size) — 批量反向小波变换。
//
// 输入:
//   values — 域元素数组, 长度必须是 size 的整数倍
//   size   — 每个子块的长度, 必须是 2 的幂 (或 0)
//
// 效果: 把 values 按 size 切分为若干子块, 每块独立做反向小波变换。
//
// 算法 (递归):
//   size=0 或 1: 无需操作 (恒等变换)
//   size=2:      b' = b - a  (展开, 避免递归开销)
//   size=4:      展开的两步内核 (优化)
//   其他:        分解 size = n1 * n2, n1 = 2^(trailing_zeros(size)/2)
//               ① 对每块做 size=n1 的反向变换
//               ② 转置 (以 n2×n1 排列)
//               ③ 对每块做 size=n2 的反向变换
//               ④ 转置回原排列 (n1×n2)
// ---------------------------------------------------------------------------
template <typename F>
void inverse_wavelet_transform_batch(std::span<F> values, std::size_t size) {
    assert(values.size() % size == 0);
    assert(is_power_of_two(size) || size == 0);

    if (size == 0 || size == 1) return;
    if (size == 2) {
        // 两个元素: b' = b - a, a 不变
        for (std::size_t off = 0; off + 2 <= values.size(); off += 2) {
            values[off + 1] = values[off + 1] - values[off];
        }
        return;
    }
    if (size == 4) {
        // 4 元素展开: 两步蝴蝶 (先做相邻对, 再做交叉对)
        for (std::size_t off = 0; off + 4 <= values.size(); off += 4) {
            values[off + 3] = values[off + 3] - values[off + 1];
            values[off + 2] = values[off + 2] - values[off];
            values[off + 3] = values[off + 3] - values[off + 2];
            values[off + 1] = values[off + 1] - values[off];
        }
        return;
    }
    // 递归: n = n1 * n2, n1 = 2^(k/2) 使得 n1 和 n2 尽量均衡
    const std::size_t n1 = std::size_t{1} << (trailing_zeros(size) / 2);
    const std::size_t n2 = size / n1;
    inverse_wavelet_transform_batch<F>(values, n1);
    transpose<F>(values, n2, n1);
    inverse_wavelet_transform_batch<F>(values, n2);
    transpose<F>(values, n1, n2);
}

// ---------------------------------------------------------------------------
// wavelet_transform_batch(values, size) — 批量前向小波变换。
//
// 输入:
//   values — 域元素数组, 长度必须是 size 的整数倍
//   size   — 每个子块的长度, 必须是 2 的幂 (或 0)
//
// 效果: 把 values 按 size 切分为若干子块, 每块独立做前向小波变换。
//
// 算法 (递归, 与反向版本对称):
//   size=0 或 1: 恒等变换
//   size=2:      b' = a + b
//   size=4:      展开的两步内核
//   size=8/16:   硬编码展开 (为性能优化, 避免递归开销)
//   其他:        与反向版本同样的 n1*n2 分解 + 转置策略
// ---------------------------------------------------------------------------
template <typename F>
void wavelet_transform_batch(std::span<F> values, std::size_t size) {
    assert(values.size() % size == 0);
    assert(is_power_of_two(size) || size == 0);

    if (size == 0 || size == 1) return;
    if (size == 2) {
        // 两个元素: b' = a + b, a 不变
        for (std::size_t off = 0; off + 2 <= values.size(); off += 2) {
            values[off + 1] = values[off + 1] + values[off];
        }
        return;
    }
    if (size == 4) {
        // 4 元素展开: 两步蝴蝶
        for (std::size_t off = 0; off + 4 <= values.size(); off += 4) {
            values[off + 1] = values[off + 1] + values[off];
            values[off + 3] = values[off + 3] + values[off + 2];
            values[off + 2] = values[off + 2] + values[off];
            values[off + 3] = values[off + 3] + values[off + 1];
        }
        return;
    }
    if (size == 8) {
        // 8 元素展开: 先做 4 个 2-元素对, 再做分组合并
        for (std::size_t off = 0; off + 8 <= values.size(); off += 8) {
            auto* v = values.data() + off;
            v[1] = v[1] + v[0];
            v[3] = v[3] + v[2];
            v[2] = v[2] + v[0];
            v[3] = v[3] + v[1];
            v[5] = v[5] + v[4];
            v[7] = v[7] + v[6];
            v[6] = v[6] + v[4];
            v[7] = v[7] + v[5];
            v[4] = v[4] + v[0];
            v[5] = v[5] + v[1];
            v[6] = v[6] + v[2];
            v[7] = v[7] + v[3];
        }
        return;
    }
    if (size == 16) {
        // 16 元素展开: 4 个 size-4 子块 → 跨块合并
        for (std::size_t off = 0; off + 16 <= values.size(); off += 16) {
            auto* v = values.data() + off;
            // 阶段 1: 4 个长度为 4 的子块独立前向变换
            for (std::size_t k = 0; k < 16; k += 4) {
                v[k + 1] = v[k + 1] + v[k];
                v[k + 3] = v[k + 3] + v[k + 2];
                v[k + 2] = v[k + 2] + v[k];
                v[k + 3] = v[k + 3] + v[k + 1];
            }
            // 阶段 2: 跨块合并 (a=v[0..4], b=v[4..8], c=v[8..12], d=v[12..16])
            for (std::size_t i = 0; i < 4; ++i) {
                v[4 + i]  = v[4 + i]  + v[0 + i];  // b += a
                v[12 + i] = v[12 + i] + v[8 + i];  // d += c
                v[8 + i]  = v[8 + i]  + v[0 + i];  // c += a
                v[12 + i] = v[12 + i] + v[4 + i];  // d += b
            }
        }
        return;
    }
    // 递归: 与反向版本同样的分解
    const std::size_t n1 = std::size_t{1} << (trailing_zeros(size) / 2);
    const std::size_t n2 = size / n1;
    wavelet_transform_batch<F>(values, n1);
    transpose<F>(values, n2, n1);
    wavelet_transform_batch<F>(values, n2);
    transpose<F>(values, n1, n2);
}

} // namespace whir::algebra::ntt
