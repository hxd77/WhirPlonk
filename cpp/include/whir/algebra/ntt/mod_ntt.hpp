#pragma once

// ============================================================================
// mod_ntt.hpp — Reed-Solomon 编码的顶层 NTT 入口
//
// 提供 ark_ntt（别名 interleaved_rs_encode）：接收一组多项式系数向量，
// 零填充至 codeword_length，执行正向 NTT（求值），并将结果转置为
// 行主序布局，其中每行对应一个求值点在所有多项式上的取值。
//
// 交错模式：每个大小为 poly_size 的多项式被切分为 interleaving_depth 个
// 大小为 message_length = poly_size / depth 的块，每块零填充至
// codeword_length 后执行 NTT。
//
// C++ 版本直接接收 NttEngine<F> 引用，而非 Rust 中的 TypeMap/TypeId 分派。
//
// 对应 Rust 源文件：src/algebra/ntt/mod.rs（ark_ntt / interleaved_rs_encode）
// ============================================================================

#include "cooley_tukey.hpp"
#include "../../profiling.hpp"

#include <cassert>
#include <cstddef>
#include <span>
#include <vector>

namespace whir::algebra::ntt {

// ark_ntt — 基于 NTT 求值的交错 Reed-Solomon 编码。
//
// 参数：
//   engine             — 提供 NTT/INTT 能力的 NttEngine<F>
//   coeffs             — 多项式系数 span 数组（所有 span 大小必须相同）
//   codeword_length    — 求值域大小（输出块长度）
//   interleaving_depth — 每个多项式被切分的块数
//
// 算法流程：
//   1. 对每个多项式和每个深度块：
//      将 message_length 个系数拷贝至 codeword_length 长度的缓冲区（零填充）
//   2. 对每个 codeword_length 块执行正向 NTT（在单位根处求值）
//   3. 将 (num_polys × depth) × codeword_length 转置为
//      codeword_length × (num_polys × depth)，得到行主序布局
//
// 返回值：大小为 codeword_length × num_polys × interleaving_depth 的平坦向量。
//   布局：result[row * num_cols + col]，其中
//     row = 求值点索引，col = (多项式, 深度块) 对。
//
// 此布局将同一求值点上的所有求值结果打包至同一行，适合作为 Merkle 树叶子数据。
template <typename F>
std::vector<F> ark_ntt(
    NttEngine<F>& engine,
    std::span<const std::span<const F>> coeffs,
    std::size_t codeword_length,
    std::size_t interleaving_depth
) {
    if (coeffs.empty()) return {};

    const std::size_t poly_size = coeffs[0].size();
    for (const auto& poly : coeffs) {
        assert(poly.size() == poly_size);
    }
    assert(poly_size % interleaving_depth == 0);

    const std::size_t message_length = poly_size / interleaving_depth;
    const std::size_t per_poly_size = codeword_length * interleaving_depth;
    const std::size_t total_size = per_poly_size * coeffs.size();

    assert(codeword_length % message_length == 0);

    // GPU 快路径：紧凑系数上传后，在 device 端完成零填充/批量 NTT/最终转置。
    std::vector<F> gpu_result;
    if (engine.try_gpu_interleaved_rs_encode(
            coeffs, codeword_length, interleaving_depth, gpu_result)) {
        return gpu_result;
    }

    // 步骤 1：零填充系数扩展。
    // 每个多项式的各块按 codeword_length 间隔排列，前 message_length 个位置
    // 存放系数，其余填零。
    std::vector<F> result(total_size, F::zero());
    {
        ::whir::profile::ScopedTimer timer("cpu", total_size, "rs_zero_pad");
        for (std::size_t poly_index = 0; poly_index < coeffs.size(); ++poly_index) {
            const auto& poly = coeffs[poly_index];
            for (std::size_t block_index = 0; block_index < interleaving_depth; ++block_index) {
                const std::size_t dst = poly_index * per_poly_size + block_index * codeword_length;
                const std::size_t src = block_index * message_length;
                for (std::size_t i = 0; i < message_length; ++i) {
                    result[dst + i] = poly[src + i];
                }
            }
        }
    }

    // 步骤 2：正向 NTT（多项式求值）。
    // 优先尝试 GPU 卸载（融合 NTT + 转置）。
    const std::size_t rows_before_transpose = coeffs.size() * interleaving_depth;
    if (engine.try_gpu_ntt_batch_transpose(
            std::span<F>{result}, codeword_length, rows_before_transpose, codeword_length)) {
        return result;
    }

    {
        ::whir::profile::ScopedTimer timer("cpu", total_size, "cpu_ntt"); //CPU版NTT计时
        engine.ntt_batch(std::span<F>{result}, codeword_length);
    }

    // 步骤 3：转置为行主序（求值点主序）布局。
    // 转置后，第 i 行包含所有多项式在第 i 个求值点处的取值。
    {
        ::whir::profile::ScopedTimer timer("cpu", total_size, "rs_transpose");
        if (rows_before_transpose != codeword_length) {
            std::vector<F> transposed(total_size);
#ifdef _OPENMP
            #pragma omp parallel for schedule(static) if(codeword_length >= 4096)
#endif
            for (std::ptrdiff_t cj = 0; cj < static_cast<std::ptrdiff_t>(codeword_length); ++cj) {
                const std::size_t j = static_cast<std::size_t>(cj);
                F* dst = transposed.data() + j * rows_before_transpose;
                for (std::size_t i = 0; i < rows_before_transpose; ++i) {
                    dst[i] = result[i * codeword_length + j];
                }
            }
            result = std::move(transposed);
        } else {
            transpose<F>(std::span<F>{result}, rows_before_transpose, codeword_length);
        }
    }
    return result;
}

// interleaved_rs_encode — ark_ntt 的语义化别名。
template <typename F>
std::vector<F> interleaved_rs_encode(
    NttEngine<F>& engine,
    std::span<const std::span<const F>> coeffs,
    std::size_t codeword_length,
    std::size_t interleaving_depth
) {
    return ark_ntt<F>(engine, coeffs, codeword_length, interleaving_depth);
}

} // namespace whir::algebra::ntt
