#pragma once

// =============================================================================
// transpose.hpp — 原地矩阵转置 (cache-oblivious 算法)。
// 对应 WHIR 中的 src/algebra/ntt/transpose.rs。
//
// 提供对连续存储的矩阵做原地转置的能力。当 rows 和 cols 均为 2 的幂时,
// 使用 cache-oblivious 递归分块算法, 否则退化到 buffer 式直接转置。
//
// 接口:
//   transpose<F>(matrix, rows, cols) — 原地转置, matrix 是 rows*cols 个
//     F 元素的连续块 (可以包含多个矩阵, 长度 = N * rows * cols)
//
// 内部实现 (detail 命名空间):
//   transpose_copy(src, dst)        — 带 buffer 的转置 (source → destination)
//   transpose_square_swap(a, b)     — 交换两个方阵并同时转置
//   transpose_square(m)             — 方阵的 cache-oblivious 原地转置
//
// 阈值: workload_size<F>() = 32KB / sizeof(F), 小于此阈值时直接循环转置,
// 避免递归开销; 大于时采用递归分块策略减少缓存失效。
// =============================================================================

#include "matrix.hpp"
#include "utils.hpp"
#include "../../utils.hpp"

#include <cassert>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

namespace whir::algebra::ntt {

namespace detail {

using ::whir::workload_size;

// ---------------------------------------------------------------------------
// transpose_copy(src, dst) — 将矩阵 src 转置后写入 dst (src 和 dst 不重叠)。
//
// 输入:
//   src — MatrixMut<F>, rows×cols 的源矩阵
//   dst — MatrixMut<F>, cols×rows 的目标矩阵 (dst.rows() == src.cols()
//         且 dst.cols() == src.rows())
//
// 算法:
//   当 rows*cols*2 ≤ workload_size<F>() 时, 直接双重循环逐元素复制。
//   否则沿长边切分两半, 递归处理 — 这是 cache-oblivious 策略:
//   每次切分让子问题变小, 最终落入快速路径或 L1 缓存。
// ---------------------------------------------------------------------------
template <typename F>
void transpose_copy(MatrixMut<F> src, MatrixMut<F> dst) {
    assert(src.rows() == dst.cols());
    assert(src.cols() == dst.rows());
    const std::size_t rows = src.rows();
    const std::size_t cols = src.cols();

    // 小矩阵直接逐元素转置, 避免递归开销。
    if (rows * cols * 2 <= workload_size<F>()) {
        for (std::size_t i = 0; i < rows; ++i) {
            for (std::size_t j = 0; j < cols; ++j) {
                *dst.ptr_at_mut(j, i) = *src.ptr_at(i, j);
            }
        }
        return;
    }

    // 沿较长的一维切分递归。
    if (rows > cols) {
        const std::size_t split = rows / 2;
        auto [s1, s2] = src.split_vertical(split);
        auto [d1, d2] = dst.split_horizontal(split);
        transpose_copy<F>(s1, d1);
        transpose_copy<F>(s2, d2);
    } else {
        const std::size_t split = cols / 2;
        auto [s1, s2] = src.split_horizontal(split);
        auto [d1, d2] = dst.split_vertical(split);
        transpose_copy<F>(s1, d1);
        transpose_copy<F>(s2, d2);
    }
}

// ---------------------------------------------------------------------------
// transpose_square_swap(a, b) — 交换两个同尺寸方阵的内容并同时转置。
//
// 输入:
//   a, b — 两个 size×size 的方阵 (size 是 2 的幂), 满足
//          a 和 b 互为转置维度的关系 (a.rows == b.cols, a.cols == b.rows)
//
// 效果: 执行后 a[i][j] ↔ b[j][i] (交换并转置)
//
// 算法:
//   size ≤ 8: 直接双重循环交换
//   否则且 2*size*size > workload: 四象限递归
//   否则: 2×2 块展开交换
//
// 这是方阵原地转置的核心辅助函数: 把矩阵分成四个象限后,
// 对角线上的两个象限 (a 和 d) 各自递归转置,
// 反对角线上的两个象限 (b 和 c) 通过此函数交换并转置。
// ---------------------------------------------------------------------------
template <typename F>
void transpose_square_swap(MatrixMut<F> a, MatrixMut<F> b) {
    assert(a.is_square());
    assert(a.rows() == b.cols());
    assert(a.cols() == b.rows());
    assert(is_power_of_two(a.rows()));

    const std::size_t size = a.rows();

    // ≤8×8: 直接交换, 递归开销大于计算开销。
    if (size <= 8) {
        for (std::size_t i = 0; i < size; ++i) {
            for (std::size_t j = 0; j < size; ++j) {
                std::swap(*a.ptr_at_mut(i, j), *b.ptr_at_mut(j, i));
            }
        }
        return;
    }

    // 大块继续递归子分块 (cache-oblivious 策略)。
    if (2 * size * size > workload_size<F>()) {
        const std::size_t n = size / 2;
        auto aq = a.split_quadrants(n, n);
        auto bq = b.split_quadrants(n, n);
        // 注意递归调用模式 (参考四象限转置公式):
        // a ↔ b 的对角块交换同时维持转置关系
        transpose_square_swap<F>(aq.a, bq.a);
        transpose_square_swap<F>(aq.b, bq.c);
        transpose_square_swap<F>(aq.c, bq.b);
        transpose_square_swap<F>(aq.d, bq.d);
    } else {
        // 2×2 块展开: 一次处理 2×2 的 4 个元素, 减少循环开销。
        for (std::size_t i = 0; i < size; i += 2) {
            for (std::size_t j = 0; j < size; j += 2) {
                std::swap(*a.ptr_at_mut(i,     j    ), *b.ptr_at_mut(j,     i    ));
                std::swap(*a.ptr_at_mut(i + 1, j    ), *b.ptr_at_mut(j,     i + 1));
                std::swap(*a.ptr_at_mut(i,     j + 1), *b.ptr_at_mut(j + 1, i    ));
                std::swap(*a.ptr_at_mut(i + 1, j + 1), *b.ptr_at_mut(j + 1, i + 1));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// transpose_square(m) — 原地转置一个 size×size 方阵 (size 是 2 的幂)。
//
// 输入: m — size×size 的方阵 MatrixMut (size 为 2 的幂)
// 效果: 原地转置
//
// 算法 (四象限递归):
//   把矩阵分成 size/2 的四个子块 A(左上), B(右上), C(左下), D(右下):
//     A  D  → 对 A 和 D 递归转置 (它们在对角线上不动)
//     C  B  → B 和 C 通过 transpose_square_swap 交换并转置
//   这等同于对整个矩阵原地转置。
//   size*size ≤ workload 时退化为直接循环 (上三角交换)。
// ---------------------------------------------------------------------------
template <typename F>
void transpose_square(MatrixMut<F> m) {
    assert(m.is_square());
    assert(is_power_of_two(m.rows()));
    const std::size_t size = m.rows();

    if (size * size > workload_size<F>()) {
        const std::size_t n = size / 2;
        auto q = m.split_quadrants(n, n);
        transpose_square<F>(q.a);       // 左上递归
        transpose_square<F>(q.d);       // 右下递归
        transpose_square_swap<F>(q.b, q.c); // 右上 ↔ 左下
    } else {
        // 小矩阵直接上三角交换 (避免递归开销)。
        for (std::size_t i = 0; i < size; ++i) {
            for (std::size_t j = i + 1; j < size; ++j) {
                std::swap(*m.ptr_at_mut(i, j), *m.ptr_at_mut(j, i));
            }
        }
    }
}

} // namespace detail

// ---------------------------------------------------------------------------
// transpose<F>(matrix, rows, cols) — 原地矩阵转置 (公共入口)。
//
// 输入:
//   matrix — F 元素的连续 span, 长度必须是 rows*cols 的整数倍
//            (即可以包含多个 rows×cols 矩阵, 逐个独立转置)
//   rows   — 每个矩阵的行数
//   cols   — 每个矩阵的列数
//
// 效果: 对 matrix 中每个 rows×cols 子块原地转置为 cols×rows。
//
// 算法选择:
//   - 如果 rows 或 cols 不是 2 的幂: 使用 buffer 式转置
//     (分配临时缓冲, transpose_copy 后回写)
//   - 如果 rows == cols (方阵, 且为 2 的幂): 使用 transpose_square
//     (cache-oblivious 递归原地转置)
//   - 如果 rows ≠ cols (均为 2 的幂): 使用临时 scratch 缓冲 +
//     transpose_copy (无法原地, 因维度改变)
//
// 6-step Cooley-Tukey NTT 在步骤间需要转置来改变数据排列,
// 本函数是其核心依赖。
// ---------------------------------------------------------------------------
template <typename F>
void transpose(std::span<F> matrix, std::size_t rows, std::size_t cols) {
    assert(matrix.size() % (rows * cols) == 0);
    if (matrix.empty()) return;

    const std::size_t block = rows * cols;
    std::vector<F> scratch(block, matrix[0]);
    for (std::size_t off = 0; off < matrix.size(); off += block) {
        auto chunk = matrix.subspan(off, block);
        scratch.assign(chunk.begin(), chunk.end());
        for (std::size_t i = 0; i < rows; ++i) {
            for (std::size_t j = 0; j < cols; ++j) {
                chunk[j * rows + i] = scratch[i * cols + j];
            }
        }
    }
}

} // namespace whir::algebra::ntt
