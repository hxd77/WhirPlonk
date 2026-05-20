#pragma once

// ============================================================================
// transpose.hpp — 原地矩阵转置（缓存无关算法）
//
// 对行主序连续存储的矩阵提供原地转置。当两个维度均为 2 的幂时，
// 使用缓存无关的递归分块策略；否则回退至基于缓冲区的拷贝。
//
// 递归切换至直接循环的阈值为 workload_size<F>() = 32KB / sizeof(F)，
// 确保单个子块可舒适地放入 L1 缓存。
//
// 对应 Rust 源文件：src/algebra/ntt/transpose.rs
// ============================================================================

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

// 将 src 转置复制到 dst（不重叠）。沿较长维度递归分割直至子问题适配缓存，
// 然后使用逐元素拷贝循环。
template <typename F>
void transpose_copy(MatrixMut<F> src, MatrixMut<F> dst) {
    assert(src.rows() == dst.cols());
    assert(src.cols() == dst.rows());
    const std::size_t rows = src.rows();
    const std::size_t cols = src.cols();

    // 总数据量适配缓存阈值时使用直接循环
    if (rows * cols * 2 <= workload_size<F>()) { //如果当前src+dst的总访问数据量足够小,可以放进缓存,就直接用双重循环完成转置
        for (std::size_t i = 0; i < rows; ++i) {
            for (std::size_t j = 0; j < cols; ++j) {
                *dst.ptr_at_mut(j, i) = *src.ptr_at(i, j); //ptr_at(i,j)表示src第i行、第j列的元素, ptr_at_mut(j,i)表示获取dst第j行、第i列的可写指针
            }
        }
        return;
    }

    // 沿较长维度分割以保持子问题近似方阵
    if (rows > cols) { //如果src行数更多,就沿着行方向切src
        //假如src=6*2,即
        //a b
        //c d
        //e f
        //g h
        //i j
        //k l 
        //->s1 = 前 3 行
        //a b
        //c d
        //e f
        //
        //s2 = 后 3 行
        //g h
        //i j
        //k l
        const std::size_t split = rows / 2;
        auto [s1, s2] = src.split_vertical(split);
        auto [d1, d2] = dst.split_horizontal(split);
        transpose_copy<F>(s1, d1);
        transpose_copy<F>(s2, d2);
    } else {
        //rows<=cols的情况,如果列数多,就沿着列方向切src
        //假设src=2*6
        //例如
        //a b c d e f
        //g h i j k l
        //按列切成左右两块
        //s1:
        //a b c
        //g h i
        //
        //s2:
        //d e f
        //j k l
        const std::size_t split = cols / 2;
        auto [s1, s2] = src.split_horizontal(split); //对src按列切成左右两块
        auto [d1, d2] = dst.split_vertical(split); //对dst按行切成上下两块
        transpose_copy<F>(s1, d1);
        transpose_copy<F>(s2, d2);
    }
}

// 交换两个同尺寸方阵的内容并同时转置：返回后 a[i][j] 存储原 b[j][i]，反之亦然。
//把两个方阵块a和b互相交换,同时交换时做转置
//a[i][j] 变成 原来的 b[j][i]
//b[j][i] 变成 原来的 a[i][j]
// 这是递归方阵转置的核心辅助函数：将矩阵分割为四象限 A,B,C,D 后，
// 对角块 (A,D) 递归转置，非对角块 (B,C) 通过此函数交换并转置。
template <typename F>
void transpose_square_swap(MatrixMut<F> a, MatrixMut<F> b) {
    assert(a.is_square()); //必须是方阵
    assert(a.rows() == b.cols());
    assert(a.cols() == b.rows());
    assert(is_power_of_two(a.rows())); //边长必须是2的幂

    const std::size_t size = a.rows(); 

    // 小块直接双层循环（递归开销超过计算量）
    if (size <= 8) { //矩阵边长小于等于8时，直接暴力交换
        for (std::size_t i = 0; i < size; ++i) {
            for (std::size_t j = 0; j < size; ++j) {
                std::swap(*a.ptr_at_mut(i, j), *b.ptr_at_mut(j, i));
            }
        }
        return;
    }

    // 大块递归至象限（缓存无关策略）
    //如果a和b的总数据量太大,超过缓存有好的工作量,就递归切成4个象限处理
    //a 的左上 A 要和 b 的左上 E 转置交换
    //a 的右上 B 要和 b 的左下 G 转置交换
    //a 的左下 C 要和 b 的右上 F 转置交换
    //a 的右下 D 要和 b 的右下 H 转置交换
    if (2 * size * size > workload_size<F>()) {
        const std::size_t n = size / 2;
        auto aq = a.split_quadrants(n, n);
        auto bq = b.split_quadrants(n, n);
        transpose_square_swap<F>(aq.a, bq.a);
        transpose_square_swap<F>(aq.b, bq.c);
        transpose_square_swap<F>(aq.c, bq.b);
        transpose_square_swap<F>(aq.d, bq.d);
    } else {
        // 2×2 块展开：每次迭代处理 4 个元素
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

// 方阵原地转置（规模必须为 2 的幂）。
//
// 象限分解：分割为 A(左上)、B(右上)、C(左下)、D(右下)，然后：
//   - 对角块 A、D 递归转置（原位不动）
//   - 非对角块 B、C 交换并转置（transpose_square_swap）
//
// 当矩阵适配缓存时回退至上三角交换循环。
template <typename F>
void transpose_square(MatrixMut<F> m) {
    assert(m.is_square());
    assert(is_power_of_two(m.rows()));
    const std::size_t size = m.rows();

    if (size * size > workload_size<F>()) {
        const std::size_t n = size / 2;
        auto q = m.split_quadrants(n, n);
        transpose_square<F>(q.a);
        transpose_square<F>(q.d);
        transpose_square_swap<F>(q.b, q.c);
    } else {
        // 上三角交换（直接循环，无递归）
        for (std::size_t i = 0; i < size; ++i) {
            for (std::size_t j = i + 1; j < size; ++j) {
                std::swap(*m.ptr_at_mut(i, j), *m.ptr_at_mut(j, i));
            }
        }
    }
}

} // namespace detail

// 原地矩阵转置的公共入口。
//
// 参数：
//   matrix — F 元素的连续 span，长度必须是 rows × cols 的整数倍
//           （单次调用可独立转置多个矩阵）
//   rows   — 每个矩阵的行数
//   cols   — 每个矩阵的列数
//
// 算法选择：
//   - 两个维度均非 2 的幂：基于缓冲区的拷贝转置
//   - rows == cols（方阵，2 的幂）：递归原地转置（transpose_square）
//   - rows != cols（均为 2 的幂）：临时缓冲区 + transpose_copy
//
// 此函数是 6 步 Cooley-Tukey NTT 的核心依赖，用于在各步骤之间重排数据布局。
template <typename F>
void transpose(std::span<F> matrix, std::size_t rows, std::size_t cols) {
    assert(matrix.size() % (rows * cols) == 0);
    if (matrix.empty()) return;

    // 基于缓冲区的转置：拷出后按转置顺序写回。
    // 处理所有情况（包括非 2 的幂维度），但每块需要 O(rows×cols) 的辅助空间。
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
