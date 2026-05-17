#pragma once

// ===========================================================================
// matrix_commit.hpp — 矩阵承诺的纯函数层
// 对应 WHIR 中的 src/protocols/matrix_commit.rs。
//
// 把域元素矩阵编码为字节, 然后对每行做哈希 — 这是 Merkle 树构建的前置步骤。
//
// WHIR 中的矩阵承诺流程:
//   matrix → encode_into → bytes → hash_rows → leaves → merkle_tree
//
// 提供:
//   encoded_size<T>()           — 单元素 LE 编码字节数 (Fp=8, Fp2=16, Fp3=24)
//   encode_into<T>(vals, out)   — 把域元素数组 LE 编码到字节缓冲
//   hash_rows(engine, ms, in, out) — 把 bytes 切成 ms 段独立哈希
//   commit_leaves<T>(engine, m, cols, out) — 编码 + 行哈希一步到位
//
// 编码格式: 每个域元素按 little-endian u64 编码基域分量。
//   Goldilocks     = [c0 的 8B LE]
//   GoldilocksExt2 = [c0 的 8B LE][c1 的 8B LE]
//   GoldilocksExt3 = [c0 的 8B LE][c1 的 8B LE][c2 的 8B LE]
//
// 对应 Rust: protocols/matrix_commit.rs + algebra/fields.rs (Encodable trait)
// ===========================================================================

#include "../algebra/goldilocks.hpp"
#include "../algebra/goldilocks_ext2.hpp"
#include "../algebra/goldilocks_ext3.hpp"
#include "../hash/hash_engine.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// ---- CUDA GPU 加速 (可选) ----
#ifdef WHIR_CUDA
#include "../../../cuda/cuda_integration.hpp"
#endif

namespace whir::protocols::matrix_commit {

// ---- 单元素编码字节数 (编译期常量) ----

template <typename T>
constexpr std::size_t encoded_size() noexcept;

template <>
constexpr std::size_t encoded_size<::whir::algebra::Goldilocks>() noexcept { return 8; } //p=2^64-2^32+1<2^64所以可以放入一个8字节的无符号整数

template <>
constexpr std::size_t encoded_size<::whir::algebra::GoldilocksExt2>() noexcept { return 16; }

template <>
constexpr std::size_t encoded_size<::whir::algebra::GoldilocksExt3>() noexcept { return 24; }

// ---- u64 LE 写入 ----
//将一个64位整数(u64)以小端序格式写入到字节数组中
inline void write_u64_le(std::uint64_t v, std::uint8_t* out) noexcept {
    for (int b = 0; b < 8; ++b) {
        out[b] = static_cast<std::uint8_t>((v >> (8 * b)) & 0xFFu);
    }
    //例如v = 0x0102030405060708->out=[08] [07] [06] [05] [04] [03] [02] [01]
}

// ---- 逐元素 LE 编码到字节缓冲 ----
//将一组Goldilocks域元素values编码为字节流out
template <typename T>
void encode_into(std::span<const T> values, std::span<std::uint8_t> out);

template <>
inline void encode_into<::whir::algebra::Goldilocks>(
    std::span<const ::whir::algebra::Goldilocks> values,
    std::span<std::uint8_t> out)
{
    constexpr std::size_t per = 8;
    assert(out.size() == values.size() * per);

    // ---- GPU 加速: 大量元素编码卸到 GPU ----
#ifdef WHIR_CUDA
    if (values.size() >= whir::cuda::GPU_NTT_THRESHOLD) {
        whir::cuda::gpu_encode_to_bytes(
            reinterpret_cast<const uint64_t*>(values.data()),
            out.data(), values.size());
        return;
    }
#endif

    // ---- CPU 路径 (带 OpenMP 可选) ----
#ifdef _OPENMP
    #pragma omp parallel for
#endif
    for (std::size_t i = 0; i < values.size(); ++i)
        write_u64_le(values[i].as_canonical_u64(), out.data() + i * per);
}

template <>
inline void encode_into<::whir::algebra::GoldilocksExt2>(
    std::span<const ::whir::algebra::GoldilocksExt2> values,
    std::span<std::uint8_t> out)
{
    constexpr std::size_t per = 16;
    assert(out.size() == values.size() * per);
#ifdef _OPENMP
    #pragma omp parallel for
#endif
    for (std::size_t i = 0; i < values.size(); ++i) {
        write_u64_le(values[i].c0().as_canonical_u64(), out.data() + i * per + 0);
        write_u64_le(values[i].c1().as_canonical_u64(), out.data() + i * per + 8);
        //假设values[0]=1 + 2x,c0() = 1 (十六进制 0x01),c1() = 2 (十六进制 0x02)
        //写入c0,out[0...7]=01 00 00 00 00 00 00 00
        //写入c1,out[8...15]=02 00 00 00 00 00 00 00
    }
}

template <>
inline void encode_into<::whir::algebra::GoldilocksExt3>(
    std::span<const ::whir::algebra::GoldilocksExt3> values,
    std::span<std::uint8_t> out)
{
    constexpr std::size_t per = 24;
    assert(out.size() == values.size() * per);
#ifdef _OPENMP
    #pragma omp parallel for
#endif
    for (std::size_t i = 0; i < values.size(); ++i) {
        write_u64_le(values[i].c0().as_canonical_u64(), out.data() + i * per +  0);
        write_u64_le(values[i].c1().as_canonical_u64(), out.data() + i * per +  8);
        write_u64_le(values[i].c2().as_canonical_u64(), out.data() + i * per + 16);
    }
}

// ---- 行哈希: 把字节缓冲切成 message_size 段分别哈希 ----

/// 将 bytes 切成 out.size() 段 (每段 message_size 字节), 每段独立哈希。
//将一大块连续的字节数据bytes按照指定的行长度拆分,然后批量计算每一行的哈希值
inline void hash_rows(
    const ::whir::hash::HashEngine& engine,
    std::size_t message_size, //每一行大小
    std::span<const std::uint8_t> bytes, //原始数据池
    std::span<::whir::hash::Hash> out) 
{
    assert(bytes.size() == message_size * out.size());
    if (message_size == 0) {
        engine.hash_many(0, std::span<const std::uint8_t>{}, out);
        return;
    }
    engine.hash_many(message_size, bytes, out);
    //假设message_size=8,每行8字节
    //out.size()=3要得到3个哈希值
    //读取 bytes[0...7]，存入 out[0]。
    //读取 bytes[8...15]，存入 out[1]。
    //读取 bytes[16...23]，存入 out[2]。
}

// ---- 一站式: 编码矩阵 + 行哈希 → 叶子哈希列表 ----

/// commit_leaves: 把矩阵 matrix (rows×cols) 按域类型 T 编码后逐行哈希。
/// matrix 长度必须 == out.size() * num_cols。
/// num_cols == 0 时每行都是空消息, out 为引擎的 size=0 常量哈希。
// 把Goldilocks64组成的二维矩阵,转换成一排哈希值。每一个行数据对应一个哈希值
template <typename T>
void commit_leaves(
    const ::whir::hash::HashEngine& engine,
    std::span<const T> matrix, //本质是一个一维数组
    std::size_t num_cols, //矩阵列数,一行有多少元素
    std::span<::whir::hash::Hash> out)
{
    assert(matrix.size() == out.size() * num_cols);
    const std::size_t per = encoded_size<T>(); //单个元素编码字节大小 Goldilocks64=8,Goldilocks64_Ext2=16
    const std::size_t message_size = per * num_cols;  // 每行编码后的字节数

    if (message_size == 0) {
        engine.hash_many(0, std::span<const std::uint8_t>{}, out);
        return;
    }

    // 一次性编码整个矩阵, 然后按行切片哈希
    std::vector<std::uint8_t> buf(matrix.size() * per); 
    encode_into<T>(matrix, std::span<std::uint8_t>{buf}); //把matrix编码成字节流buf
    engine.hash_many(message_size, std::span<const std::uint8_t>{buf}, out); //对buf哈希输出到out,每个out[i]的大小是message字节
    //假设matrix:[A,B,C,D](matrix.size=4),num_col=2,out_size=2(2行)
    //message_size=16字节,每一行编码占16字节
    //buf:4*8=32字节大小,encode_into: 把ABCD变成字节填满buf
    //buf 前 16 字节：[A的字节][B的字节] (第一行) buf 后 16 字节：[C的字节][D的字节] (第二行)送入hash的是16字节,输出是32字节
    //然后执行hash_many: out[0]=Hash(A+B)=32字节,out[1] = Hash(C + D)=32字节
}

} // namespace whir::protocols::matrix_commit
