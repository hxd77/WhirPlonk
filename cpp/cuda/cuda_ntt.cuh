// =============================================================================
// cuda_ntt.cuh — CUDA NTT 内核声明与设备端辅助函数
//
// 提供 GPU 加速的有限域 NTT (Number Theoretic Transform) 操作:
//   - Radix-2 蝴蝶内核  (最常用的基 2 变换)
//   - Twiddle 因子乘法  (6-step 算法的第 4 步)
//   - 矩阵转置          (6-step 算法的第 1/3/6 步)
//   - 域元素编码        (域元素 → 字节数组, 用于叶子哈希)
//
// 所有内核针对 Goldilocks 64-bit 域 (p = 2^64 - 2^32 + 1) 优化,
// 使用 128-bit 中间运算处理模乘, 每个 thread 独立处理一对蝴蝶或一个元素。
//
// 线程模型:
//   - 每个 thread block 处理一个独立的 NTT 批次或矩阵块
//   - blockDim.x = 256 (适配 SM 占用率)
//   - gridDim 根据数据规模自动计算
//
// 要求: CUDA 架构 ≥ 7.0 (Volta+), 编译标志 -arch=sm_75 或更高
// =============================================================================

#pragma once

#include <cuda_runtime.h>
#include <cstdint>

// ---------------------------------------------------------------------------
// Goldilocks 域常量 (与 CPU 端一致)
// p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001
// R  = 2^64 (Montgomery 乘法的 R 因子)
// ---------------------------------------------------------------------------
namespace cuda_goldilocks {

__device__ __constant__ constexpr uint64_t P           = 0xFFFFFFFF00000001ULL;
__device__ __constant__ constexpr uint64_t MU          = 0xFFFFFFFFULL;  // p 的 Montgomery 逆: -p⁻¹ mod 2^64
__device__ __constant__ constexpr uint64_t R_SQ_MOD_P  = 0xFFFFFFFE00000001ULL; // R² mod p (用于进入 Montgomery 域)

// ---- 设备端域运算 (内联, 每个函数处理一对或多对元素) ----

/// Goldilocks 规范表示乘法: a * b mod p.
/// 对标 CPU 端 Goldilocks::reduce128_parts(lo, hi).
__device__ __forceinline__ uint64_t mont_mul(uint64_t a, uint64_t b) {
    uint64_t lo = a * b;
    uint64_t hi = __umul64hi(a, b);
    uint32_t hi_hi = static_cast<uint32_t>(hi >> 32);
    uint32_t hi_lo = static_cast<uint32_t>(hi);

    uint64_t t0 = lo >= hi_hi ? lo - hi_hi : P - (static_cast<uint64_t>(hi_hi) - lo);
    uint64_t t1 = static_cast<uint64_t>(hi_lo) * MU;
    uint64_t sum = t0 + t1;
    if (sum < t0 || sum >= P) sum -= P;
    return sum;
}

/// Montgomery 加法: (a + b) mod p
__device__ __forceinline__ uint64_t mont_add(uint64_t a, uint64_t b) {
    uint64_t r = a + b;
    if (r >= P || r < a) r -= P;  // 进位或溢出 → 减去 p
    return r;
}

/// Montgomery 减法: (a - b) mod p
__device__ __forceinline__ uint64_t mont_sub(uint64_t a, uint64_t b) {
    if (a < b) return a + P - b;
    return a - b;
}

/// 输入已经是规范表示.
__device__ __forceinline__ uint64_t from_mont(uint64_t a) {
    return a;
}

/// 输入已经是规范表示.
__device__ __forceinline__ uint64_t to_mont(uint64_t a) {
    return a;
}

} // namespace cuda_goldilocks

// =============================================================================
// 内核函数声明
// =============================================================================

/// Radix-2 NTT 蝴蝶内核
///
/// 每个 thread 处理一对 (a, b) → (a + b*w, a - b*w)
/// 输入数组包含多个 size-2 的独立块, grid 覆盖所有块。
///
/// @param data    域元素数组 (Montgomery 表示), 原地修改
/// @param roots   单位根表 (Montgomery 表示), 长度 = n
/// @param n       每个独立 NTT 批次的元素总数
/// @param stride  单位根步长: 根表中使用的索引 = (pair_idx % (n/2)) * stride
__global__ void ntt_radix2_kernel(
    uint64_t* data, const uint64_t* roots,
    uint32_t n, uint32_t stride, uint32_t batches);

/// 四阶 Cooley-Tukey 内核 (合并两层 butterfly + twiddle)
///
/// 每个 thread 处理一个独立的 size-4 块.
/// 比两次 size-2 调用减少了一半的全局内存访问。
__global__ void ntt_radix4_kernel(
    uint64_t* data, const uint64_t* roots,
    uint32_t n, uint32_t stride, uint32_t batches);

/// 小规模直接 NTT 内核.
/// 每个 CUDA block 处理一个批次, 支持 n <= 16.
__global__ void ntt_small_kernel(
    uint64_t* data, const uint64_t* roots,
    uint32_t n, uint32_t stride, uint32_t roots_len, uint32_t batches);

/// Twiddle 因子乘法内核
///
/// 6-step NTT 第 4 步: 对 rows×cols 矩阵的第 i 行第 j 列乘以 roots[i*j].
/// 每个 thread 处理一个矩阵元素 (第 0 行和第 0 列跳过, twiddle=1).
///
/// @param data  矩阵数据 (row-major), 原地修改
/// @param roots 单位根表
/// @param rows  矩阵行数
/// @param cols  矩阵列数
/// @param step  根表缩放步长 = roots_len / (rows*cols)
__global__ void apply_twiddles_kernel(
    uint64_t* data, const uint64_t* roots,
    uint32_t rows, uint32_t cols, uint32_t step, uint32_t batches);

/// 矩阵转置内核 (out-of-place, 通过共享内存)
///
/// 6-step NTT 第 1/3/6 步: 将 rows×cols 矩阵转置到独立输出缓冲.
/// 使用 shared memory tile 优化全局内存合并访问.
///
/// @param src   输入矩阵数据 (row-major, rows×cols 个元素)
/// @param dst   输出矩阵数据 (row-major, cols×rows 个元素)
/// @param rows  原始行数
/// @param cols  原始列数
__global__ void transpose_kernel(
    const uint64_t* src, uint64_t* dst, uint32_t rows, uint32_t cols, uint32_t batches);

/// Reed-Solomon 编码输入打包内核.
///
/// 输入是紧凑的 coeffs[poly][coeff]，输出是已经清零的
/// out[poly][interleaving_block][codeword_index]。每个 thread 复制一个
/// 原始系数到对应块的前 message_length 个位置，零填充由 cudaMemset 完成。
__global__ void pack_rs_coeffs_kernel(
    const uint64_t* coeffs, uint64_t* out,
    uint32_t poly_size, uint32_t codeword_length,
    uint32_t interleaving_depth, uint32_t num_polys);

/// 域元素编码内核: 将 Montgomery 域元素转为 LE 字节
///
/// 每个 thread 处理一个域元素.
/// 对标 CPU 端的 write_u64_le(Goldilocks::as_canonical_u64()).
///
/// @param values  域元素数组 (Montgomery 表示)
/// @param out     输出字节数组 (每元素 8 字节, LE)
/// @param count   元素个数
__global__ void encode_to_bytes_kernel(
    const uint64_t* values, uint8_t* out, uint32_t count);

/// SHA-256 批量哈希内核.
/// 每个 thread 处理一条固定长度消息 input[i*message_size ..) 并输出 32 字节 digest.
__global__ void sha256_hash_many_kernel(
    const uint8_t* input, uint8_t* output, uint32_t message_size, uint32_t count);

/// SHA-256 Goldilocks leaf 哈希内核.
/// 每个 thread 处理转置后矩阵的一行: from_mont(values) -> LE 字节流 -> digest.
__global__ void sha256_hash_goldilocks_rows_kernel(
    const uint64_t* input, uint8_t* output, uint32_t row_elements, uint32_t count);

/// 指定 Merkle node index 的 32B hash gather 内核.
/// 每个 thread 复制一个 hash: out[i] = nodes[node_indices[i]].
__global__ void gather_hashes_kernel(
    const uint8_t* nodes, const uint64_t* node_indices, uint8_t* out, uint32_t count);

/// GoldilocksExt3 编码内核: 三个基域分量分别编码
/// 每元素 24 字节 = c0(8B) + c1(8B) + c2(8B), 均为 LE
__global__ void encode_ext3_to_bytes_kernel(
    const uint64_t* c0, const uint64_t* c1, const uint64_t* c2,
    uint8_t* out, uint32_t count);
