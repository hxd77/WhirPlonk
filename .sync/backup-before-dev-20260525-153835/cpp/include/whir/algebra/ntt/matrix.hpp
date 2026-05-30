#pragma once

// ============================================================================
// matrix.hpp — 带步长的可变矩阵视图
//
// MatrixMut<T> 是对连续内存区域的非拥有视图，解释为 rows × cols 矩阵，
// 行步长（row_stride）可大于 cols。用于原地转置算法中引用子矩阵，
// 无需拷贝数据。
//
// 设计要点：
//   - 分割时保留 row_stride（不收缩至 cols），子视图仍指向原始存储。
//   - at()/operator() 带边界检查（assert）；ptr_at()/ptr_at_mut() 跳过检查，
//     用于性能关键路径。
//   - 构造函数为 private；实例通过 from_mut_slice() 或 split_* 系列方法创建。
//
// 对应 Rust 源文件：src/algebra/ntt/matrix.rs
// ============================================================================

#include <cassert>
#include <cstddef>
#include <span>
#include <utility>

namespace whir::algebra::ntt {

template <typename T>
class MatrixMut {
public:
    // 从平坦的可变 span 构造稠密矩阵视图，row_stride 设为 cols（行连续）。
    static MatrixMut from_mut_slice(std::span<T> slice, std::size_t rows, std::size_t cols) {
        assert(slice.size() == rows * cols);
        return MatrixMut{slice.data(), rows, cols, cols};
    }

    constexpr std::size_t rows() const noexcept { return rows_; } //返回行
    constexpr std::size_t cols() const noexcept { return cols_; } //返回列
    constexpr bool is_square() const noexcept { return rows_ == cols_; }

    //返回矩阵第row行的可变视图
    //假设矩阵是
    //rows_ = 3
    //cols_ = 4
    //
    //a00 a01 a02 a03
    //a10 a11 a12 a13
    //a20 a21 a22 a23

    //输出返回a10,a11,a12,a13
    std::span<T> row(std::size_t row) {
        assert(row < rows_);
        return std::span<T>{data_ + row * row_stride_, cols_};
    }

    // 把矩阵按照行方向切成上下两部分
    //a00 a01 a02
    //a10 a11 a12
    //a20 a21 a22
    //a30 a31 a32

    //输入row=2,结果
    //top:
    //a00 a01 a02
    //a10 a11 a12
    //
    //
    //bottom:
    //
    //a20 a21 a22
    //a30 a31 a32
    std::pair<MatrixMut, MatrixMut> split_vertical(std::size_t row) const {
        assert(row <= rows_);
        return {
            MatrixMut{data_, row, cols_, row_stride_},
            MatrixMut{data_ + row * row_stride_, rows_ - row, cols_, row_stride_},
        };
    }

    // 把矩阵按照列方向切成左右两部分
    // 假如矩阵
    // a00 a01 a02 a03
    //a10 a11 a12 a13
    //a20 a21 a22 a23
    //输入col=2,输出
    //left:
    //a00 a01
    //a10 a11
    //a20 a21
    //
    //
    //right:
    //
    //a02 a03
    //a12 a13
    //a22 a23
    std::pair<MatrixMut, MatrixMut> split_horizontal(std::size_t col) const {
        assert(col <= cols_);
        return {
            MatrixMut{data_, rows_, col, row_stride_}, //起点:原矩阵开头,行数:rows_,列数:col,行跨度:row_stride_
            MatrixMut{data_ + col, rows_, cols_ - col, row_stride_}, //起点:第col列的地址,行数:rows_,列数;cols-col,行跨度:row_stride_
        };
    }

    // 分割为四个象限。递归转置算法使用此方法将方阵分解为子块。
    struct Quadrants { MatrixMut a; MatrixMut b; MatrixMut c; MatrixMut d; };
    Quadrants split_quadrants(std::size_t row, std::size_t col) const {
        auto [u, l] = split_vertical(row); //先按行切成上下两块u、l
        auto [a, b] = u.split_horizontal(col); //把u切成左右两块a,b
        auto [c, d] = l.split_horizontal(col); //把l切成左右两块c,d
        return Quadrants{a, b, c, d};
    }

    // 交换矩阵中两个元素的位置。若位置相同则无操作。
    void swap_entries(std::size_t r1, std::size_t c1, std::size_t r2, std::size_t c2) {
        assert(r1 < rows_ && c1 < cols_);
        assert(r2 < rows_ && c2 < cols_);
        if (r1 == r2 && c1 == c2) return;
        std::swap(*ptr_at_mut(r1, c1), *ptr_at_mut(r2, c2));
    }

    // 带边界检查的元素访问（用于调试/测试）。
    T& at(std::size_t r, std::size_t c) {
        assert(r < rows_ && c < cols_);
        return data_[r * row_stride_ + c];
    }
    const T& at(std::size_t r, std::size_t c) const {
        assert(r < rows_ && c < cols_);
        return data_[r * row_stride_ + c];
    }

    // 无检查的裸指针访问（用于性能关键路径）。
    T* ptr_at_mut(std::size_t r, std::size_t c) noexcept {
        return data_ + r * row_stride_ + c;
    }
    const T* ptr_at(std::size_t r, std::size_t c) const noexcept {
        return data_ + r * row_stride_ + c;
    }

private:
    constexpr MatrixMut(T* data, std::size_t rows, std::size_t cols, std::size_t row_stride) noexcept
        : data_(data), rows_(rows), cols_(cols), row_stride_(row_stride) {}

    T* data_;
    std::size_t rows_; //行
    std::size_t cols_; //列
    std::size_t row_stride_; //行跨度:从一行开头到下一行开头,需要跨过多少个元素
};

} // namespace whir::algebra::ntt
