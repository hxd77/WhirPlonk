#pragma once

// ============================================================================
// matrix_commit.hpp — 域元素矩阵承诺（编码 + 逐行哈希）
//
// 将域元素矩阵编码为字节并对每行独立哈希。这是 IRS 承诺协议中
// Merkle 树构建之前的预处理步骤。
//
// 流水线:
//   matrix -> encode_into -> bytes -> hash_rows -> leaves -> merkle_tree
//
// 提供的功能:
//   encoded_size<T>()             — 每元素 LE 编码大小（8/16/24 字节）
//   encode_into<T>(vals, out)     — 将域元素编码到字节缓冲区（LE）
//   hash_rows(engine, ms, in, out) — 将字节按 ms 大小分块，逐块哈希
//   commit_leaves<T>(engine, m, cols, out) — 一步完成编码 + 逐行哈希
//
// 编码格式（每个基域分量为小端 u64）:
//   Goldilocks     = [c0: 8B LE]
//   GoldilocksExt2 = [c0: 8B LE][c1: 8B LE]
//   GoldilocksExt3 = [c0: 8B LE][c1: 8B LE][c2: 8B LE]
//
// 对应 Rust 文件: src/protocols/matrix_commit.rs + algebra/fields.rs (Encodable)
// ============================================================================

#include "../algebra/goldilocks.hpp"
#include "../algebra/goldilocks_ext2.hpp"
#include "../algebra/goldilocks_ext3.hpp"
#include "../hash/hash_engine.hpp"
#include "../profiling.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// ---- 可选 CUDA GPU 加速 ----
#ifdef WHIR_CUDA
#include "../../../cuda/cuda_integration.hpp"
#endif

namespace whir::protocols::matrix_commit {

// ---- 每元素编码大小（编译期常量） ----

template <typename T>
constexpr std::size_t encoded_size() noexcept;

template <>
constexpr std::size_t encoded_size<::whir::algebra::Goldilocks>() noexcept { return 8; }

template <>
constexpr std::size_t encoded_size<::whir::algebra::GoldilocksExt2>() noexcept { return 16; }

template <>
constexpr std::size_t encoded_size<::whir::algebra::GoldilocksExt3>() noexcept { return 24; }

// ---- u64 小端写入 ----

/// 将 64 位整数按小端序写入 @p out（8 字节）。
inline void write_u64_le(std::uint64_t v, std::uint8_t* out) noexcept {
    for (int b = 0; b < 8; ++b) {
        out[b] = static_cast<std::uint8_t>((v >> (8 * b)) & 0xFFu);
    }
}

// ---- 逐元素 LE 编码到字节缓冲区 ----

/// 将域元素 span 按小端序编码到字节缓冲区。
///
/// @pre out.size() == values.size() * encoded_size<T>()
template <typename T>
void encode_into(std::span<const T> values, std::span<std::uint8_t> out);

template <>
inline void encode_into<::whir::algebra::Goldilocks>(
    std::span<const ::whir::algebra::Goldilocks> values,
    std::span<std::uint8_t> out)
{
    constexpr std::size_t per = 8;
    assert(out.size() == values.size() * per);

#ifdef WHIR_CUDA
    if (whir::cuda::gpu_dispatch_enabled() &&
        values.size() >= whir::cuda::GPU_NTT_THRESHOLD) {
        whir::cuda::gpu_encode_to_bytes(
            reinterpret_cast<const uint64_t*>(values.data()),
            out.data(), values.size());
        return;
    }
#endif

#ifdef _OPENMP
    #pragma omp parallel for
#endif
    for (std::ptrdiff_t si = 0; si < static_cast<std::ptrdiff_t>(values.size()); ++si) {
        const std::size_t i = static_cast<std::size_t>(si);
        write_u64_le(values[i].as_canonical_u64(), out.data() + i * per);
    }
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
    for (std::ptrdiff_t si = 0; si < static_cast<std::ptrdiff_t>(values.size()); ++si) {
        const std::size_t i = static_cast<std::size_t>(si);
        write_u64_le(values[i].c0().as_canonical_u64(), out.data() + i * per + 0);
        write_u64_le(values[i].c1().as_canonical_u64(), out.data() + i * per + 8);
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
    for (std::ptrdiff_t si = 0; si < static_cast<std::ptrdiff_t>(values.size()); ++si) {
        const std::size_t i = static_cast<std::size_t>(si);
        write_u64_le(values[i].c0().as_canonical_u64(), out.data() + i * per +  0);
        write_u64_le(values[i].c1().as_canonical_u64(), out.data() + i * per +  8);
        write_u64_le(values[i].c2().as_canonical_u64(), out.data() + i * per + 16);
    }
}

// ---- 逐行哈希: 将字节缓冲区按 message_size 分块，逐块哈希 ----

/// 以 @p message_size 为单位对平坦字节缓冲区进行哈希。
///
/// @pre bytes.size() == message_size * out.size()
/// @param message_size  每行字节数（一个哈希输入）
/// @param out           输出 span；out[i] = hash(bytes[i*ms .. (i+1)*ms])
inline void hash_rows(
    const ::whir::hash::HashEngine& engine,
    std::size_t message_size,
    std::span<const std::uint8_t> bytes,
    std::span<::whir::hash::Hash> out)
{
    assert(bytes.size() == message_size * out.size());
    if (message_size == 0) {
        engine.hash_many(0, std::span<const std::uint8_t>{}, out);
        return;
    }
    engine.hash_many(message_size, bytes, out);
}

// ---- 一步完成: 编码矩阵 + 逐行哈希 -> 叶子哈希 ----

/// 编码域元素矩阵并对每行哈希。
///
/// @tparam T        域元素类型（Goldilocks / Ext2 / Ext3）
/// @param matrix    平坦行优先数组，长度 == out.size() * num_cols
/// @param num_cols  每行列数
/// @param out       输出: out[i] = hash(encode(matrix[i*nc .. (i+1)*nc]))
///
/// 当 num_cols == 0 时，每行为空消息哈希。
template <typename T>
void commit_leaves(
    const ::whir::hash::HashEngine& engine,
    std::span<const T> matrix,
    std::size_t num_cols,
    std::span<::whir::hash::Hash> out)
{
    assert(matrix.size() == out.size() * num_cols);
    const std::size_t per = encoded_size<T>();
    const std::size_t message_size = per * num_cols;

    if (message_size == 0) {
        engine.hash_many(0, std::span<const std::uint8_t>{}, out);
        return;
    }

    // 将整个矩阵编码到字节缓冲区，然后逐行哈希
    std::vector<std::uint8_t> buf(matrix.size() * per);
    {
        ::whir::profile::ScopedTimer timer("cpu", matrix.size(), "merkle_leaf_encode");
        encode_into<T>(matrix, std::span<std::uint8_t>{buf});
    }
    {
        ::whir::profile::ScopedTimer timer("cpu", out.size(), "merkle_leaf_hash");
        engine.hash_many(message_size, std::span<const std::uint8_t>{buf}, out);
    }
}

} // namespace whir::protocols::matrix_commit
