#pragma once

// ============================================================================
// wavelet.hpp — 快速小波变换（FWT）
//
// 对连续的元素对 (a, b) 施加线性变换核：
//   正向：a' = a,      b' = a + b
//   逆向：a' = a,      b' = b - a
//
// 输入长度必须为 2 的幂。批量变体对每个连续的 size 元素块独立变换。
//
// 与 NTT 类似，小波变换是系数表示和求值表示之间的可逆线性映射，
// 但使用小波基，在 WHIR 协议中可简化折叠操作。
//
// 对应 Rust 源文件：src/algebra/ntt/wavelet.rs
// ============================================================================

#include "transpose.hpp"
#include "utils.hpp"

#include <cassert>
#include <cstddef>
#include <span>

namespace whir::algebra::ntt {

//把数组分成若干个大小为size的块,每块独立正向变换
template <typename F>
void wavelet_transform_batch(std::span<F> values, std::size_t size);

//把数组分成若干个大小为size的块,每块独立逆变换
template <typename F>
void inverse_wavelet_transform_batch(std::span<F> values, std::size_t size);
       
// 对整个 span 执行正向小波变换。前置条件：values.size() 为 2 的幂。
template <typename F>
void wavelet_transform(std::span<F> values) {
    assert(is_power_of_two(values.size()));
    wavelet_transform_batch<F>(values, values.size());
}

// 对整个 span 执行逆小波变换。前置条件：values.size() 为 2 的幂。
template <typename F>
void inverse_wavelet_transform(std::span<F> values) {
    assert(is_power_of_two(values.size()));
    inverse_wavelet_transform_batch<F>(values, values.size());
}

// 批量逆小波变换。
//
// 每个 size 元素块独立变换。分解策略：size = n1 × n2，
// 其中 n1 = 2^(trailing_zeros(size)/2)，然后依次执行
// FWT(n1) → 转置 → FWT(n2) → 转置回来。
// 小规模（2, 4）使用展开实现以避免递归开销。
template <typename F>
void inverse_wavelet_transform_batch(std::span<F> values, std::size_t size) {
    assert(values.size() % size == 0);
    assert(is_power_of_two(size) || size == 0);

    if (size == 0 || size == 1) return;
    if (size == 2) {
        for (std::size_t off = 0; off + 2 <= values.size(); off += 2) {
            values[off + 1] = values[off + 1] - values[off];
        }
        return;
    }
    if (size == 4) {
        for (std::size_t off = 0; off + 4 <= values.size(); off += 4) {
            values[off + 3] = values[off + 3] - values[off + 1];
            values[off + 2] = values[off + 2] - values[off];
            values[off + 3] = values[off + 3] - values[off + 2];
            values[off + 1] = values[off + 1] - values[off];
        }
        return;
    }
    const std::size_t n1 = std::size_t{1} << (trailing_zeros(size) / 2);
    const std::size_t n2 = size / n1;
    inverse_wavelet_transform_batch<F>(values, n1);
    transpose<F>(values, n2, n1);
    inverse_wavelet_transform_batch<F>(values, n2);
    transpose<F>(values, n1, n2);
}

// 批量正向小波变换。
//
// 与逆变换使用相同的分解策略。小规模（2, 4, 8, 16）使用展开实现以提升性能。
template <typename F>
void wavelet_transform_batch(std::span<F> values, std::size_t size) {
    assert(values.size() % size == 0);
    assert(is_power_of_two(size) || size == 0);

    if (size == 0 || size == 1) return;
    //[a0, a1]->[a0, a1+a0]
    if (size == 2) {
        for (std::size_t off = 0; off + 2 <= values.size(); off += 2) {
            values[off + 1] = values[off + 1] + values[off];
        }
        return;
    }
    //假设输入是[a, b, c, d]
    //最终输出
    //[
    //  a,
    //  b + a,
    //  c + a,
    //  d + c + b + a
    //]
    if (size == 4) {
        for (std::size_t off = 0; off + 4 <= values.size(); off += 4) {
            values[off + 1] = values[off + 1] + values[off];
            values[off + 3] = values[off + 3] + values[off + 2];
            values[off + 2] = values[off + 2] + values[off];
            values[off + 3] = values[off + 3] + values[off + 1];
        }
        return;
    }

    //假如输入是[v0, v1, v2, v3, v4, v5, v6, v7]
    if (size == 8) {
        // 展开的 8 元素 FWT：四对 2 元素蝶形，然后跨块合并
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
        // 展开的 16 元素 FWT：四个规模 4 的子块，然后跨块合并
        for (std::size_t off = 0; off + 16 <= values.size(); off += 16) {
            auto* v = values.data() + off;
            // 阶段 1：对每个规模 4 的子块独立执行 FWT
            for (std::size_t k = 0; k < 16; k += 4) {
                v[k + 1] = v[k + 1] + v[k];
                v[k + 3] = v[k + 3] + v[k + 2];
                v[k + 2] = v[k + 2] + v[k];
                v[k + 3] = v[k + 3] + v[k + 1];
            }
            // 阶段 2：跨块累加（a,b,c,d = v[0..4], v[4..8], v[8..12], v[12..16]）
            for (std::size_t i = 0; i < 4; ++i) {
                v[4 + i]  = v[4 + i]  + v[0 + i];  // b += a
                v[12 + i] = v[12 + i] + v[8 + i];  // d += c
                v[8 + i]  = v[8 + i]  + v[0 + i];  // c += a
                v[12 + i] = v[12 + i] + v[4 + i];  // d += b
            }
        }
        return;
    }
    // 规模 > 16 时使用递归分解
    const std::size_t n1 = std::size_t{1} << (trailing_zeros(size) / 2);
    const std::size_t n2 = size / n1;
    wavelet_transform_batch<F>(values, n1);
    transpose<F>(values, n2, n1);
    wavelet_transform_batch<F>(values, n2);
    transpose<F>(values, n1, n2);
}

} // namespace whir::algebra::ntt
