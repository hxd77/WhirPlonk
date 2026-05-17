#pragma once

// =============================================================================
// mod_ntt.hpp — NTT 顶层入口: RS 编码与多项式求值。
// 对应 WHIR 中 src/algebra/ntt/mod.rs 的 ark_ntt / interleaved_rs_encode。
//
// C++ 端去掉了 TypeMap / TypeId 全局派发, 改为直接接受调用方提供的
// NttEngine<F> 引用, 无全局状态。
//
// 提供:
//   ark_ntt<F>(engine, coeffs, codeword_length, interleaving_depth)
//     — 交错 Reed-Solomon 编码: 把多个多项式的系数做 NTT 求值,
//       输出行优先排列的码字矩阵
//   interleaved_rs_encode<F>(...) — ark_ntt 的别名, 语义更明确
// =============================================================================

#include "cooley_tukey.hpp"

#include <cassert>
#include <cstddef>
#include <span>
#include <vector>

namespace whir::algebra::ntt {

// ---------------------------------------------------------------------------
// ark_ntt<F>(engine, coeffs, codeword_length, interleaving_depth)
//   — 交错 Reed-Solomon 编码 (NTT 求值版)。
//
// 输入:
//   engine              — NttEngine<F> 引用, 提供 NTT/INTT 能力及单位根
//   coeffs              — 多项式系数列表, 每个 span 是一个多项式的系数
//                         所有多项式必须有相同长度 poly_size
//   codeword_length     — 编码后每个交错块的码字长度 (求值点个数)
//   interleaving_depth  — 交错深度, 每个多项式被切成 interleaving_depth 块
//
// 过程:
//   1. 断言 poly_size % interleaving_depth == 0
//      令 message_length = poly_size / interleaving_depth
//   2. 断言 codeword_length % message_length == 0 (码率是整数倍)
//   3. 为每个多项式的每个交错块分配 codeword_length 的零填充缓冲区,
//      前 message_length 个位置填入系数 (零填充到 codeword_length)
//   4. 对每个 codeword_length 长的子向量做正向 NTT (求值)
//   5. 整体转置: 把 (num_polys * interleaving_depth) × codeword_length
//      矩阵转置为 codeword_length × (num_polys * interleaving_depth)
//      — 即行主序排列的码字矩阵
//
// 输出:
//   vector<F> 长度为 total_size = codeword_length * num_polys * interleaving_depth
//   布局: matrix[row][col] = result[row * num_cols + col]
//   其中 num_cols = num_polys * interleaving_depth
//   每行对应一个求值点, 每列对应一个 (多项式, 交错块) 对。
//
// 对应 Rust: ark_ntt::<F>(engine, coeffs, codeword_length, interleaving_depth)
// ---------------------------------------------------------------------------

//接受一组多项式系数,把它们分块、补零拓展,然后通过NTT将其转换为点值表示,最后重新排列内存布局,以便后续更高效地构建Merkle Tree
template <typename F>
std::vector<F> ark_ntt(
    NttEngine<F>& engine,
    std::span<const std::span<const F>> coeffs,//多项式集合
    std::size_t codeword_length, //码长
    std::size_t interleaving_depth //交错深度:一个多项式切分为多个短的块
) {
    if (coeffs.empty()) return {};

    //假设输入coeffs包含P0和P1,P0=[a0,a1,a2,a3], P1=[b0,b1,b2,b3]
    //interleaving_depth=2(每个多项式被切成2块) ,codeword_length=4(NTT求值域大小)
    const std::size_t poly_size = coeffs[0].size(); 
    for (const auto& poly : coeffs) { //每个多项式的系数个数都相等
        assert(poly.size() == poly_size);
    }
    assert(poly_size % interleaving_depth == 0);

    //每个多项式块包含的真实系数个数
    //message_length=4/2=2(每个块的实际系数)
    const std::size_t message_length = poly_size / interleaving_depth;     
    
    //一个多项式经过补零拓展后占用的长度
    //per_poly_size=4*2=8(单个多项式扩展后的总长)
    const std::size_t per_poly_size = codeword_length * interleaving_depth;
    
    //total_size=8*2=16(整个结果数组的大小)
    const std::size_t total_size = per_poly_size * coeffs.size();

    assert(codeword_length % message_length == 0);

    // 步骤 1-3: 系数展开 + 零填充
    // 对每个多项式, 把其 interleaving_depth 个块按 codeword_length 间隔铺开,
    // 每个块的前 message_length 个位置填系数, 后面填 0。
    std::vector<F> result(total_size, F::zero());
    for (std::size_t poly_index = 0; poly_index < coeffs.size(); ++poly_index) {
        //处理P0
        //处理P1
        const auto& poly = coeffs[poly_index];

        //块0,块1
        //块0,块1
        for (std::size_t block_index = 0; block_index < interleaving_depth; ++block_index) {
            
            const std::size_t dst = poly_index * per_poly_size + block_index * codeword_length;
            const std::size_t src = block_index * message_length;
            
            //取出前2个系数[a0,a1],取出后两个系数[a2,a3]
            //取出前2个系数[b0,b1],取出后两个系数[b2,b3]
            for (std::size_t i = 0; i < message_length; ++i) {
                result[dst + i] = poly[src + i];
                //result=[a0,a1,0,0] result=[a0,a1,0,0,a2,a3,0,0]
                //result=[a0,a1,0,0,a2,a3,0,0,b1,b2,0,0] result=[a0,a1,0,0,a2,a3,0,0,b1,b2,0,0,b3,b4,0,0]
            }
        }
    }

    // 步骤 4: 每段 codeword_length 做 NTT (多项式求值)
    //系数变成在x0,x1,x2,x3这四个点上的求值结果
    //[a0, a1, 0, 0] 变换后变成在四个点上的值：[A00, A01, A02, A03]
    //[a2, a3, 0, 0] 变换后变成：[A10, A11, A12, A13]
    //
    //[b0, b1, 0, 0] 变换后变成：[B00, B01, B02, B03]
    //
    //[b2, b3, 0, 0] 变换后变成：[B10, B11, B12, B13]

    engine.ntt_batch(std::span<F>{result}, codeword_length);
    //result=[A00, A01, A02, A03,  A10, A11, A12, A13,  B00, B01, B02, B03,  B10, B11, B12, B13]

    // 步骤 5: 转置为行优先 (行 = 求值点索引, 列 = 多项式*depth)
    //所有多项式在同一个点xi上的求值打包在一起,作为Merkle Tree的一个叶子节点

    //转置,行数=求值点数,列数=块数
    transpose<F>(std::span<F>{result}, coeffs.size() * interleaving_depth, codeword_length);
    return result;
    //x0=[A00, A10, B00, B10] 叶子0
    //x1=[A01, A11, B01, B11] 叶子1
    //x2=[A02, A12, B02, B12] 叶子2
    //x3=[A03, A13, B03, B13] 叶子3
}

// ---------------------------------------------------------------------------
// interleaved_rs_encode<F>(engine, coeffs, codeword_length, interleaving_depth)
//   — ark_ntt 的别名, 语义等同于 "交错 Reed-Solomon 编码"。
// 输入/输出: 与 ark_ntt 完全一致。
// ---------------------------------------------------------------------------
template <typename F>
std::vector<F> interleaved_rs_encode(
    NttEngine<F>& engine, //ntt引擎
    std::span<const std::span<const F>> coeffs, //多项式系数
    std::size_t codeword_length, //码长
    std::size_t interleaving_depth //交错深度
) {
    return ark_ntt<F>(engine, coeffs, codeword_length, interleaving_depth);
}

} // namespace whir::algebra::ntt
