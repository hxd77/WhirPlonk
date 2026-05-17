#pragma once

// =============================================================================
// matrix.hpp — 矩阵可变视图 (strided matrix view)。
// 对应 WHIR 中的 src/algebra/ntt/matrix.rs。
//
// MatrixMut<T> 是一个轻量级视图: 不持有数据, 只记录基址、行数、列数和行步长。
// 用于 transpose 等原地转置算法中对子矩阵的引用操作。
//
// 关键设计:
//   - row_stride 在切分子矩阵时保持原矩阵的步长不变,
//     因此 split_* 产生的子视图仍然指向原数据的不同区域。
//   - at() / operator() 带边界检查 (assert), 适合调试。
//   - ptr_at() / ptr_at_mut() 不带边界检查, 性能关键路径用。
//   - 构造器私有, 只能通过 from_mut_slice() 或 split_* 方法创建。
// =============================================================================

#include <cassert>
#include <cstddef>
#include <span>
#include <utility>

namespace whir::algebra::ntt {

template <typename T>
class MatrixMut {
public:
    // -----------------------------------------------------------------------
    // from_mut_slice(slice, rows, cols) — 从平坦可变切片构造稠密矩阵视图。
    // 输入: slice — rows*cols 个连续 T 元素的可变 span
    //       rows  — 行数
    //       cols  — 列数 (也是行步长 row_stride)
    // 输出: MatrixMut 视图, row_stride = cols (稠密布局)
    // 断言: slice.size() == rows * cols
    // -----------------------------------------------------------------------
    static MatrixMut from_mut_slice(std::span<T> slice, std::size_t rows, std::size_t cols) {
        assert(slice.size() == rows * cols);
        return MatrixMut{slice.data(), rows, cols, cols};
    }

    constexpr std::size_t rows() const noexcept { return rows_; }
    constexpr std::size_t cols() const noexcept { return cols_; }
    constexpr bool is_square() const noexcept { return rows_ == cols_; }

    // -----------------------------------------------------------------------
    // row(r) — 获取第 r 行的可变 span。
    // 输入: row — 行索引 (0 ≤ row < rows)
    // 输出: std::span<T>, 长度 = cols, 指向该行在内存中连续的 cols 个元素
    // 注意: 因为 row_stride 可能 > cols (来自父矩阵切分), 所以不同行之间
    //       可能不连续, 但同一行内是连续的。
    // -----------------------------------------------------------------------
    std::span<T> row(std::size_t row) {
        assert(row < rows_);
        return std::span<T>{data_ + row * row_stride_, cols_};
    }

    // -----------------------------------------------------------------------
    // split_vertical(row) — 水平切割 (沿行方向分成上下两块)。
    // 输入: row — 上半部分的行数
    // 输出: pair<MatrixMut, MatrixMut>
    //       .first  = 上方的 row 行子矩阵
    //       .second = 下方的 rows-row 行子矩阵
    // 两个子矩阵共享同一 data_ 存储, 仅指针偏移。
    // -----------------------------------------------------------------------
    std::pair<MatrixMut, MatrixMut> split_vertical(std::size_t row) const {
        assert(row <= rows_);
        return {
            MatrixMut{data_, row, cols_, row_stride_},
            MatrixMut{data_ + row * row_stride_, rows_ - row, cols_, row_stride_},
        };
    }

    // -----------------------------------------------------------------------
    // split_horizontal(col) — 垂直切割 (沿列方向分成左右两块)。
    // 输入: col — 左半部分的列数
    // 输出: pair<MatrixMut, MatrixMut>
    //       .first  = 左侧 col 列子矩阵
    //       .second = 右侧 cols-col 列子矩阵
    // -----------------------------------------------------------------------
    std::pair<MatrixMut, MatrixMut> split_horizontal(std::size_t col) const {
        assert(col <= cols_);
        return {
            MatrixMut{data_, rows_, col, row_stride_},
            MatrixMut{data_ + col, rows_, cols_ - col, row_stride_},
        };
    }

    // -----------------------------------------------------------------------
    // split_quadrants(row, col) — 四象限切分。
    // 输入: row — 上半部分行数; col — 左半部分列数
    // 输出: Quadrants { a, b, c, d }
    //       a = 左上 (row × col)      b = 右上 (row × (cols-col))
    //       c = 左下 ((rows-row) × col)  d = 右下
    // 递归转置算法中把方阵分成四个子块时使用。
    // -----------------------------------------------------------------------
    struct Quadrants { MatrixMut a; MatrixMut b; MatrixMut c; MatrixMut d; };
    Quadrants split_quadrants(std::size_t row, std::size_t col) const {
        auto [u, l] = split_vertical(row);
        auto [a, b] = u.split_horizontal(col);
        auto [c, d] = l.split_horizontal(col);
        return Quadrants{a, b, c, d};
    }

    // -----------------------------------------------------------------------
    // swap_entries(r1,c1, r2,c2) — 交换矩阵中两个元素。
    // 输入: (r1,c1), (r2,c2) — 两个位置的行列索引
    // 效果: 原地交换两个元素的值; 若位置相同则无操作
    // 断言: 两个位置均在矩阵范围内
    // -----------------------------------------------------------------------
    void swap_entries(std::size_t r1, std::size_t c1, std::size_t r2, std::size_t c2) {
        assert(r1 < rows_ && c1 < cols_);
        assert(r2 < rows_ && c2 < cols_);
        if (r1 == r2 && c1 == c2) return;
        std::swap(*ptr_at_mut(r1, c1), *ptr_at_mut(r2, c2));
    }

    // -----------------------------------------------------------------------
    // at(r, c) — 带边界检查的元素访问 (可变/常引用)。
    // 输入: r — 行索引; c — 列索引
    // 输出: T& 或 const T&; 越界时 assert 触发
    // 用于调试和测试, 性能敏感路径请用 ptr_at / ptr_at_mut
    // -----------------------------------------------------------------------
    T& at(std::size_t r, std::size_t c) {
        assert(r < rows_ && c < cols_);
        return data_[r * row_stride_ + c];
    }
    const T& at(std::size_t r, std::size_t c) const {
        assert(r < rows_ && c < cols_);
        return data_[r * row_stride_ + c];
    }

    // -----------------------------------------------------------------------
    // ptr_at_mut(r,c) / ptr_at(r,c) — 无边界检查的裸指针访问。
    // 输入: r — 行索引; c — 列索引
    // 输出: T* (可变) 或 const T* (只读)
    // 用于 NTT/转置等性能关键路径, 调用方保证索引合法。
    // -----------------------------------------------------------------------
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
    std::size_t rows_;
    std::size_t cols_;
    std::size_t row_stride_;
};

} // namespace whir::algebra::ntt
