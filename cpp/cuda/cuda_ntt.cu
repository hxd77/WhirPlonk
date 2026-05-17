// =============================================================================
// cuda_ntt.cu — CUDA NTT 内核实现 + 启动包装
//
// 所有内核针对 4090 (SM 8.9, 128 SM, 16K cores) 调优:
//   - Block size = 256 threads (适配 4090 的 1536 max threads/SM)
//   - 使用 shared memory 进行 tile 转置 (减少全局内存事务)
//   - 合并的全局内存访问模式 (coalesced loads/stores)
//
// 编译: nvcc -arch=sm_89 -O3 cuda_ntt.cu -c
// =============================================================================

#include "cuda_ntt.cuh"

using namespace cuda_goldilocks;

// ---- 常量 ----
static constexpr uint32_t BLOCK_SIZE = 256;  // threads per block

// =============================================================================
// Radix-2 NTT 蝴蝶内核
//
// 算法: 对于 data 中每个连续的 size 元素块:
//   将块视为 size/2 对 (a, b), 每对独立计算:
//     a' = a + b * w
//     b' = a - b * w
//   其中 w = roots[(pair_idx % half_size) * stride]
//
// 线程映射: thread i 处理第 i 对, 跨 block 覆盖所有对。
//   global_tid = blockIdx.x * blockDim.x + threadIdx.x
//   每对偏移   = (global_tid % half_size) * 2 + (global_tid / half_size) * n
// =============================================================================
__global__ void ntt_radix2_kernel(
    uint64_t* data, const uint64_t* roots,
    uint32_t n, uint32_t stride)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t half_n = n / 2;
    uint32_t batch = tid / half_n;          // 哪个 NTT 批次
    uint32_t pair  = tid % half_n;          // 批次内的哪个蝴蝶对
    uint32_t total_pairs = half_n * ((blockDim.x * gridDim.x + half_n - 1) / half_n);

    // 每个 thread 可能处理多对 (grid-stride loop)
    for (; tid < total_pairs; tid += blockDim.x * gridDim.x) {
        batch = tid / half_n;
        pair  = tid % half_n;
        uint32_t base  = batch * n;                  // 批次起始偏移
        uint32_t off_a = base + pair * 2;            // a 的位置
        uint32_t off_b = off_a + 1;                  // b 的位置

        uint64_t a = data[off_a];
        uint64_t b = data[off_b];
        uint64_t w = roots[pair * stride];           // 单位根 (Montgomery 域)

        uint64_t bw = mont_mul(b, w);                // b * w mod p
        data[off_a] = mont_add(a, bw);               // a' = a + b*w
        data[off_b] = mont_sub(a, bw);               // b' = a - b*w
    }
}

// =============================================================================
// 四阶 Cooley-Tukey 内核
//
// 算法: 对 data 中每个 size-4 块, 执行两层蝴蝶 + twiddle:
//   第 1 层 (分离):
//     v0' = v0 + v2,  v2' = v0 - v2
//     v1' = v1 + v3,  v3' = v1 - v3
//   乘 twiddle:  v3' *= ω₄
//   第 2 层 (组合):
//     v0'' = v0' + v1',  v1'' = v0' - v1'
//     v2'' = v2' + v3',  v3'' = v2' - v3'
//   位逆序: swap(v1'', v2'')
//
// 每个 thread 处理一个完整的 size-4 块.
// =============================================================================
__global__ void ntt_radix4_kernel(
    uint64_t* data, const uint64_t* roots,
    uint32_t n, uint32_t stride)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t num_blocks = (n + 3) / 4;
    uint32_t total_blocks = num_blocks * ((blockDim.x * gridDim.x + num_blocks - 1) / num_blocks);

    for (uint32_t bid = tid; bid < total_blocks; bid += blockDim.x * gridDim.x) {
        uint32_t batch = bid / num_blocks;
        uint32_t blk   = bid % num_blocks;
        uint32_t base  = batch * n + blk * 4;
        uint32_t pair_root = blk * stride;  // twiddle 单位根索引

        // 加载 4 个元素到寄存器
        uint64_t v0 = data[base + 0];
        uint64_t v1 = data[base + 1];
        uint64_t v2 = data[base + 2];
        uint64_t v3 = data[base + 3];

        // 第 1 层: 奇偶分离
        uint64_t a02p = mont_add(v0, v2);
        uint64_t a02m = mont_sub(v0, v2);
        uint64_t a13p = mont_add(v1, v3);
        uint64_t a13m = mont_sub(v1, v3);

        v0 = a02p; v2 = a02m;
        v1 = a13p;
        v3 = mont_mul(a13m, roots[pair_root]);          // twiddle: v3 *= ω₄

        // 第 2 层: 前后半各自 size-2 NTT
        uint64_t b01p = mont_add(v0, v1);
        uint64_t b01m = mont_sub(v0, v1);
        uint64_t b23p = mont_add(v2, v3);
        uint64_t b23m = mont_sub(v2, v3);

        // 写出 + 位逆序 (v1 ↔ v2)
        data[base + 0] = b01p;
        data[base + 1] = b23p;   // 原 v2 位置
        data[base + 2] = b01m;   // 原 v1 位置 (位逆序交换)
        data[base + 3] = b23m;
    }
}

// =============================================================================
// Twiddle 因子乘法内核
//
// 算法: 对于 rows×cols 矩阵的每个元素 (i, j):
//   若 i==0 或 j==0: twiddle = 1 (跳过)
//   否则:           data[i][j] *= roots[(i * step) % roots_len]
//   其中乘法使用 Montgomery 域乘法.
//
// 线程映射: thread 处理全局索引, 跳过第 0 行和第 0 列.
// =============================================================================
__global__ void apply_twiddles_kernel(
    uint64_t* data, const uint64_t* roots,
    uint32_t rows, uint32_t cols, uint32_t step)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t total = rows * cols;

    for (uint32_t idx = tid; idx < total; idx += blockDim.x * gridDim.x) {
        uint32_t i = idx / cols;  // 行号
        uint32_t j = idx % cols;  // 列号
        if (i == 0 || j == 0) continue;  // 跳过第 0 行和第 0 列

        uint32_t root_idx = (i * step * j) % (total * step);  // 单位根索引
        // 简化: roots 长度 = total * step, 使用乘积索引
        uint32_t r = (static_cast<uint64_t>(i) * j * step) % (total * step);
        data[idx] = mont_mul(data[idx], roots[r]);
    }
}

// =============================================================================
// 矩阵转置内核 (通过 shared memory tile)
//
// 算法: 将 rows×cols 矩阵切分为 TILE_DIM×TILE_DIM 的 tile,
//   每个 tile 通过 shared memory 完成转置.
//
// 线程映射: 2D thread block (TILE_DIM, TILE_DIM),
//   覆盖 src_tile[i][j] → dst_tile[j][i].
// =============================================================================
static constexpr uint32_t TILE_DIM = 32;  // 32×32 = 1024 个线程, 与 block size 匹配

__global__ void transpose_kernel(
    uint64_t* data, uint32_t rows, uint32_t cols)
{
    __shared__ uint64_t tile[TILE_DIM][TILE_DIM + 1];  // +1 避免 bank conflict

    uint32_t bx = blockIdx.x * TILE_DIM;  // 当前 tile 在 cols 维的起始位置
    uint32_t by = blockIdx.y * TILE_DIM;  // 当前 tile 在 rows 维的起始位置
    uint32_t tx = threadIdx.x;            // thread 在 tile 内的列
    uint32_t ty = threadIdx.y;            // thread 在 tile 内的行

    // 源位置 (在原始矩阵中)
    uint32_t src_row = by + ty;
    uint32_t src_col = bx + tx;
    // 目标位置 (在转置后矩阵中) — 交换行列
    uint32_t dst_row = bx + ty;
    uint32_t dst_col = by + tx;

    // 从全局内存读取到 shared memory tile
    if (src_row < rows && src_col < cols)
        tile[ty][tx] = data[src_row * cols + src_col];

    __syncthreads();

    // 从 shared memory 写出到全局内存 (交换行列访问)
    if (dst_row < cols && dst_col < rows) {
        // 转置后: dst_row 对应原始列, dst_col 对应原始行
        // 只处理上半三角避免重复交换 (方阵时)
        if (rows == cols) {
            if (src_row < src_col)  // 只交换上三角
                data[dst_row * rows + dst_col] = tile[ty][tx];
        } else {
            data[dst_row * rows + dst_col] = tile[ty][tx];
        }
    }
}

// =============================================================================
// 域元素编码内核: Montgomery 域元素 → LE 字节
//
// 每 thread 处理一个元素: from_mont → write_u64_le → out
// 对标 CPU 端: write_u64_le(values[i].as_canonical_u64(), out + i*8)
// =============================================================================
__global__ void encode_to_bytes_kernel(
    const uint64_t* values, uint8_t* out, uint32_t count)
{
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint64_t v = from_mont(values[idx]);         // 退出 Montgomery 域
    uint8_t* dst = out + idx * 8;
    // 小端序写入 (对应 CPU write_u64_le)
    for (int b = 0; b < 8; ++b)
        dst[b] = static_cast<uint8_t>((v >> (8 * b)) & 0xFFu);
}

// =============================================================================
// GoldilocksExt3 编码内核
//
// Ext3 元素 = c0 + c1·x + c2·x², 三个独立基域分量.
// 每元素 24 字节, 各分量独立写 LE.
// =============================================================================
__global__ void encode_ext3_to_bytes_kernel(
    const uint64_t* c0, const uint64_t* c1, const uint64_t* c2,
    uint8_t* out, uint32_t count)
{
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint8_t* dst = out + idx * 24;
    uint64_t v0 = from_mont(c0[idx]);
    uint64_t v1 = from_mont(c1[idx]);
    uint64_t v2 = from_mont(c2[idx]);
    for (int b = 0; b < 8; ++b) {
        dst[b + 0]  = static_cast<uint8_t>((v0 >> (8 * b)) & 0xFFu);
        dst[b + 8]  = static_cast<uint8_t>((v1 >> (8 * b)) & 0xFFu);
        dst[b + 16] = static_cast<uint8_t>((v2 >> (8 * b)) & 0xFFu);
    }
}

// =============================================================================
// 内核启动包装 — C++ 函数, 计算 grid/block 维度后启动 CUDA kernel
//
// 这些函数在 .cu 中实现以便 nvcc 编译 <<<>>> 语法.
// 外部通过 cuda_ntt.hpp 中的声明调用.
// =============================================================================

#include "cuda_ntt.hpp"
#include <algorithm>  // std::min

namespace whir::cuda {

static constexpr uint32_t BLOCK = 256;
static constexpr uint32_t BLOCK_2D = 32;

void launch_ntt_radix2(uint64_t* data, const uint64_t* roots,
                       uint32_t n, uint32_t stride) {
    uint32_t half_n = n / 2;
    uint32_t grid = div_up(half_n, BLOCK);
    grid = std::min(grid, 4096u);
    ntt_radix2_kernel<<<grid, BLOCK>>>(data, roots, n, stride);
    CUDA_CHECK(cudaGetLastError());
}

void launch_ntt_radix4(uint64_t* data, const uint64_t* roots,
                       uint32_t n, uint32_t stride) {
    uint32_t n_blocks = n / 4;
    uint32_t grid = div_up(n_blocks, BLOCK);
    grid = std::min(grid, 4096u);
    ntt_radix4_kernel<<<grid, BLOCK>>>(data, roots, n, stride);
    CUDA_CHECK(cudaGetLastError());
}

void launch_apply_twiddles(uint64_t* data, const uint64_t* roots,
                           uint32_t rows, uint32_t cols, uint32_t step) {
    uint32_t total = rows * cols;
    uint32_t grid = div_up(total, BLOCK);
    grid = std::min(grid, 4096u);
    apply_twiddles_kernel<<<grid, BLOCK>>>(data, roots, rows, cols, step);
    CUDA_CHECK(cudaGetLastError());
}

void launch_transpose(uint64_t* data, uint32_t rows, uint32_t cols) {
    dim3 block(BLOCK_2D, BLOCK_2D);
    dim3 grid(div_up(cols, BLOCK_2D), div_up(rows, BLOCK_2D));
    transpose_kernel<<<grid, block>>>(data, rows, cols);
    CUDA_CHECK(cudaGetLastError());
}

void launch_encode_to_bytes(const uint64_t* values, uint8_t* out, uint32_t count) {
    uint32_t grid = div_up(count, BLOCK);
    grid = std::min(grid, 4096u);
    encode_to_bytes_kernel<<<grid, BLOCK>>>(values, out, count);
    CUDA_CHECK(cudaGetLastError());
}

void launch_encode_ext3_to_bytes(const uint64_t* c0, const uint64_t* c1,
                                  const uint64_t* c2, uint8_t* out, uint32_t count) {
    uint32_t grid = div_up(count, BLOCK);
    grid = std::min(grid, 4096u);
    encode_ext3_to_bytes_kernel<<<grid, BLOCK>>>(c0, c1, c2, out, count);
    CUDA_CHECK(cudaGetLastError());
}

} // namespace whir::cuda
