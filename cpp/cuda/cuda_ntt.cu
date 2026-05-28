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
    uint32_t n, uint32_t stride, uint32_t batches)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t half_n = n / 2;
    uint32_t batch = tid / half_n;          // 哪个 NTT 批次
    uint32_t pair  = tid % half_n;          // 批次内的哪个蝴蝶对
    // 每个 thread 可能处理多对 (grid-stride loop)
    for (; tid < half_n * batches; tid += blockDim.x * gridDim.x) {
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
    uint32_t n, uint32_t stride, uint32_t batches)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t num_blocks = (n + 3) / 4;
    uint32_t total_blocks = num_blocks * batches;

    for (uint32_t bid = tid; bid < total_blocks; bid += blockDim.x * gridDim.x) {
        uint32_t batch = bid / num_blocks;
        uint32_t blk   = bid % num_blocks;
        uint32_t base  = batch * n + blk * 4;
        uint32_t pair_root = stride;  // size-4 twiddle 单位根索引

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
    uint32_t rows, uint32_t cols, uint32_t step, uint32_t batches)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t matrix_size = rows * cols;
    uint32_t total = matrix_size * batches;

    for (uint32_t idx = tid; idx < total; idx += blockDim.x * gridDim.x) {
        uint32_t local = idx % matrix_size;
        uint32_t i = local / cols;  // 行号
        uint32_t j = local % cols;  // 列号
        if (i == 0 || j == 0) continue;  // 跳过第 0 行和第 0 列

        uint32_t r = (static_cast<uint64_t>(i) * j * step) % (matrix_size * step);
        data[idx] = mont_mul(data[idx], roots[r]);
    }
}

// =============================================================================
// 矩阵转置内核 (out-of-place)
//
// 每个 thread 处理一个矩阵元素。该版本比 tiled shared-memory 版本在 T400
// 上更快；主要瓶颈仍是递归层级和全局内存流量，而非单次 tile 内重排。
// =============================================================================
__global__ void transpose_kernel(
    const uint64_t* src, uint64_t* dst, uint32_t rows, uint32_t cols, uint32_t batches)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t matrix_size = rows * cols;
    uint32_t total = matrix_size * batches;
    for (uint32_t idx = tid; idx < total; idx += blockDim.x * gridDim.x) {
        uint32_t batch = idx / matrix_size;
        uint32_t local = idx % matrix_size;
        uint32_t row = local / cols;
        uint32_t col = local % cols;
        dst[batch * matrix_size + col * rows + row] = src[idx];
    }
}

// =============================================================================
// Reed-Solomon 编码输入打包内核
//
// 输入:  coeffs[poly_index * poly_size + coeff_index]
// 输出:  out[poly_index * (codeword_length * depth)
//           + block_index * codeword_length + intra_block_index]
//
// 每个 thread 复制一个原始系数。out 由 host 侧 cudaMemset 预先清零，因此
// codeword 中 message_length 之后的元素自然保持为 0。
// =============================================================================
__global__ void pack_rs_coeffs_kernel(
    const uint64_t* coeffs, uint64_t* out,
    uint32_t poly_size, uint32_t codeword_length,
    uint32_t interleaving_depth, uint32_t num_polys)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t total_coeffs = poly_size * num_polys;
    uint32_t message_length = poly_size / interleaving_depth;
    uint32_t per_poly_size = codeword_length * interleaving_depth;

    for (uint32_t idx = tid; idx < total_coeffs; idx += blockDim.x * gridDim.x) {
        uint32_t poly = idx / poly_size;
        uint32_t coeff = idx % poly_size;
        uint32_t block = coeff / message_length;
        uint32_t intra = coeff % message_length;
        out[poly * per_poly_size + block * codeword_length + intra] = coeffs[idx];
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
    for (; idx < count; idx += blockDim.x * gridDim.x) {
        uint64_t v = from_mont(values[idx]);         // 退出 Montgomery 域
        uint8_t* dst = out + static_cast<uint64_t>(idx) * 8u;
        // 小端序写入 (对应 CPU write_u64_le)
        for (int b = 0; b < 8; ++b)
            dst[b] = static_cast<uint8_t>((v >> (8 * b)) & 0xFFu);
    }
}

// =============================================================================
// SHA-256 批量哈希内核
//
// 每个 thread 处理一条独立消息。此实现优先保证确定性和工程切点清晰，
// 用于把 RS leaf bytes 留在 GPU 上并只回传 32B leaf hashes。
// =============================================================================
__device__ __constant__ uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

__device__ __forceinline__ uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

__device__ __forceinline__ uint32_t load_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

__device__ __forceinline__ void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    #pragma unroll
    for (int i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
    #pragma unroll
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    #pragma unroll
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__global__ void sha256_hash_many_kernel(
    const uint8_t* input, uint8_t* output, uint32_t message_size, uint32_t count)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    for (uint32_t msg = tid; msg < count; msg += blockDim.x * gridDim.x) {
        const uint8_t* src = input + static_cast<uint64_t>(msg) * message_size;
        uint8_t* dst = output + static_cast<uint64_t>(msg) * 32u;
        uint32_t state[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
        };

        uint32_t full_blocks = message_size / 64u;
        for (uint32_t b = 0; b < full_blocks; ++b) {
            uint8_t block[64];
            #pragma unroll
            for (int i = 0; i < 64; ++i) block[i] = src[b * 64u + i];
            sha256_compress(state, block);
        }

        uint8_t block[64] = {};
        uint32_t rem = message_size & 63u;
        for (uint32_t i = 0; i < rem; ++i) block[i] = src[full_blocks * 64u + i];
        block[rem] = 0x80u;
        if (rem >= 56u) {
            sha256_compress(state, block);
            #pragma unroll
            for (int i = 0; i < 64; ++i) block[i] = 0;
        }
        const uint64_t bit_len = static_cast<uint64_t>(message_size) * 8u;
        #pragma unroll
        for (int i = 0; i < 8; ++i) {
            block[63 - i] = static_cast<uint8_t>((bit_len >> (8 * i)) & 0xffu);
        }
        sha256_compress(state, block);

        #pragma unroll
        for (int i = 0; i < 8; ++i) {
            dst[i * 4 + 0] = static_cast<uint8_t>(state[i] >> 24);
            dst[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            dst[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            dst[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
    }
}

__device__ __forceinline__ void store_goldilocks_le_element(uint64_t value, uint8_t* dst)
{
    const uint64_t v = from_mont(value);
    #pragma unroll
    for (int b = 0; b < 8; ++b) {
        dst[b] = static_cast<uint8_t>((v >> (8u * b)) & 0xffu);
    }
}

// =============================================================================
// BLAKE3 批量哈希内核
// =============================================================================
__device__ __constant__ uint32_t BLAKE3_IV_CUDA[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

__device__ __constant__ uint8_t BLAKE3_MSG_PERM_CUDA[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
};

__device__ __forceinline__ uint32_t rotr32_blake3(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

__device__ __forceinline__ uint32_t load_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

__device__ __forceinline__ void store_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

__device__ __forceinline__ void blake3_g(uint32_t state[16], uint32_t a, uint32_t b,
                                         uint32_t c, uint32_t d, uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32_blake3(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32_blake3(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32_blake3(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32_blake3(state[b] ^ state[c], 7);
}

__device__ __forceinline__ void blake3_round(uint32_t state[16], const uint32_t msg[16]) {
    blake3_g(state, 0, 4, 8, 12, msg[0], msg[1]);
    blake3_g(state, 1, 5, 9, 13, msg[2], msg[3]);
    blake3_g(state, 2, 6, 10, 14, msg[4], msg[5]);
    blake3_g(state, 3, 7, 11, 15, msg[6], msg[7]);
    blake3_g(state, 0, 5, 10, 15, msg[8], msg[9]);
    blake3_g(state, 1, 6, 11, 12, msg[10], msg[11]);
    blake3_g(state, 2, 7, 8, 13, msg[12], msg[13]);
    blake3_g(state, 3, 4, 9, 14, msg[14], msg[15]);
}

__device__ __forceinline__ void blake3_permute(uint32_t msg[16]) {
    uint32_t tmp[16];
#pragma unroll
    for (int i = 0; i < 16; ++i) tmp[i] = msg[BLAKE3_MSG_PERM_CUDA[i]];
#pragma unroll
    for (int i = 0; i < 16; ++i) msg[i] = tmp[i];
}

__device__ __forceinline__ void blake3_compress_in_place_cuda(
    uint32_t cv[8], const uint8_t block[64], uint32_t block_len, uint32_t flags)
{
    uint32_t block_words[16];
#pragma unroll
    for (int i = 0; i < 16; ++i) block_words[i] = load_le32(block + i * 4);

    uint32_t state[16];
#pragma unroll
    for (int i = 0; i < 8; ++i) state[i] = cv[i];
    state[8] = BLAKE3_IV_CUDA[0];
    state[9] = BLAKE3_IV_CUDA[1];
    state[10] = BLAKE3_IV_CUDA[2];
    state[11] = BLAKE3_IV_CUDA[3];
    state[12] = 0u;
    state[13] = 0u;
    state[14] = block_len;
    state[15] = flags;

#pragma unroll
    for (int round = 0; round < 7; ++round) {
        blake3_round(state, block_words);
        if (round != 6) blake3_permute(block_words);
    }

#pragma unroll
    for (int i = 0; i < 8; ++i) cv[i] = state[i] ^ state[i + 8];
}

__device__ __forceinline__ void blake3_hash_fixed_cuda(
    const uint8_t* src, uint32_t message_size, uint8_t* dst)
{
    uint32_t cv[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) cv[i] = BLAKE3_IV_CUDA[i];

    const uint32_t blocks = message_size / 64u;
    for (uint32_t b = 0; b < blocks; ++b) {
        uint8_t block[64];
#pragma unroll
        for (int i = 0; i < 64; ++i) block[i] = src[b * 64u + i];
        uint32_t flags = 0u;
        if (b == 0) flags |= 1u;
        if (b + 1u == blocks) flags |= 2u | 8u;
        blake3_compress_in_place_cuda(cv, block, 64u, flags);
    }

#pragma unroll
    for (int i = 0; i < 8; ++i) store_le32(dst + i * 4, cv[i]);
}

__global__ void blake3_hash_many_kernel(
    const uint8_t* input, uint8_t* output, uint32_t message_size, uint32_t count)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    for (uint32_t msg = tid; msg < count; msg += blockDim.x * gridDim.x) {
        blake3_hash_fixed_cuda(
            input + static_cast<uint64_t>(msg) * message_size,
            message_size,
            output + static_cast<uint64_t>(msg) * 32u);
    }
}

__global__ void blake3_hash_goldilocks_rows_kernel(
    const uint64_t* input, uint8_t* output, uint32_t row_elements, uint32_t count)
{
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t message_size = row_elements * 8u;
    for (uint32_t msg = tid; msg < count; msg += blockDim.x * gridDim.x) {
        const uint64_t* src = input + static_cast<uint64_t>(msg) * row_elements;
        uint8_t* dst = output + static_cast<uint64_t>(msg) * 32u;
        uint32_t cv[8];
#pragma unroll
        for (int i = 0; i < 8; ++i) cv[i] = BLAKE3_IV_CUDA[i];

        const uint32_t blocks = message_size / 64u;
        for (uint32_t b = 0; b < blocks; ++b) {
            uint8_t block[64];
#pragma unroll
            for (int e = 0; e < 8; ++e) {
                store_goldilocks_le_element(src[b * 8u + static_cast<uint32_t>(e)], block + e * 8);
            }
            uint32_t flags = 0u;
            if (b == 0) flags |= 1u;
            if (b + 1u == blocks) flags |= 2u | 8u;
            blake3_compress_in_place_cuda(cv, block, 64u, flags);
        }

#pragma unroll
        for (int i = 0; i < 8; ++i) store_le32(dst + i * 4, cv[i]);
    }
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
    for (; idx < count; idx += blockDim.x * gridDim.x) {
        uint8_t* dst = out + static_cast<uint64_t>(idx) * 24u;
        uint64_t v0 = from_mont(c0[idx]);
        uint64_t v1 = from_mont(c1[idx]);
        uint64_t v2 = from_mont(c2[idx]);
        for (int b = 0; b < 8; ++b) {
            dst[b + 0]  = static_cast<uint8_t>((v0 >> (8 * b)) & 0xFFu);
            dst[b + 8]  = static_cast<uint8_t>((v1 >> (8 * b)) & 0xFFu);
            dst[b + 16] = static_cast<uint8_t>((v2 >> (8 * b)) & 0xFFu);
        }
    }
}

__global__ void encode_ext2_to_bytes_kernel(
    const uint64_t* c0, const uint64_t* c1,
    uint8_t* out, uint32_t count)
{
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    for (; idx < count; idx += blockDim.x * gridDim.x) {
        uint8_t* dst = out + static_cast<uint64_t>(idx) * 16u;
        uint64_t v0 = from_mont(c0[idx]);
        uint64_t v1 = from_mont(c1[idx]);
        for (int b = 0; b < 8; ++b) {
            dst[b + 0] = static_cast<uint8_t>((v0 >> (8 * b)) & 0xFFu);
            dst[b + 8] = static_cast<uint8_t>((v1 >> (8 * b)) & 0xFFu);
        }
    }
}

__global__ void gather_hashes_kernel(
    const uint8_t* nodes, const uint64_t* node_indices, uint8_t* out, uint32_t count)
{
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    for (; idx < count; idx += blockDim.x * gridDim.x) {
        const uint8_t* src = nodes + node_indices[idx] * 32u;
        uint8_t* dst = out + static_cast<uint64_t>(idx) * 32u;
        #pragma unroll
        for (int b = 0; b < 32; ++b) dst[b] = src[b];
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

void launch_ntt_radix2(uint64_t* data, const uint64_t* roots,
                       uint32_t n, uint32_t stride, uint32_t batches, cudaStream_t stream) {
    uint32_t total_pairs = (n / 2) * batches;
    uint32_t grid = div_up(total_pairs, BLOCK);
    grid = std::min(grid, 4096u);
    ntt_radix2_kernel<<<grid, BLOCK, 0, stream>>>(data, roots, n, stride, batches);
    CUDA_CHECK(cudaGetLastError());
}

void launch_ntt_radix4(uint64_t* data, const uint64_t* roots,
                       uint32_t n, uint32_t stride, uint32_t batches, cudaStream_t stream) {
    uint32_t total_blocks = (n / 4) * batches;
    uint32_t grid = div_up(total_blocks, BLOCK);
    grid = std::min(grid, 4096u);
    ntt_radix4_kernel<<<grid, BLOCK, 0, stream>>>(data, roots, n, stride, batches);
    CUDA_CHECK(cudaGetLastError());
}

void launch_apply_twiddles(uint64_t* data, const uint64_t* roots,
                           uint32_t rows, uint32_t cols, uint32_t step, uint32_t batches,
                           cudaStream_t stream) {
    uint32_t total = rows * cols * batches;
    uint32_t grid = div_up(total, BLOCK);
    grid = std::min(grid, 4096u);
    apply_twiddles_kernel<<<grid, BLOCK, 0, stream>>>(data, roots, rows, cols, step, batches);
    CUDA_CHECK(cudaGetLastError());
}

//在CPU端启动一个CUDA kernel,让GPU去做矩阵转置
void launch_transpose(const uint64_t* src, uint64_t* dst, uint32_t rows, uint32_t cols,
                      uint32_t batches, cudaStream_t stream) {
    uint32_t total = rows * cols * batches;
    uint32_t grid = div_up(total, BLOCK);
    grid = std::min(grid, 4096u);
    transpose_kernel<<<grid, BLOCK, 0, stream>>>(src, dst, rows, cols, batches);
    CUDA_CHECK(cudaGetLastError());
}

//启动一个CUDA kernel，把原始多项式系数coeffs重新排列/打包到GPU输出矩阵out里
void launch_pack_rs_coeffs(const uint64_t* coeffs, uint64_t* out,
                           uint32_t poly_size, uint32_t codeword_length,
                           uint32_t interleaving_depth, uint32_t num_polys,
                           cudaStream_t stream) {
    uint32_t total = poly_size * num_polys;
    uint32_t grid = div_up(total, BLOCK);
    grid = std::min(grid, 4096u);
    pack_rs_coeffs_kernel<<<grid, BLOCK, 0, stream>>>(coeffs, out, poly_size, codeword_length,
                                                      interleaving_depth, num_polys);
    CUDA_CHECK(cudaGetLastError());
}

void launch_encode_to_bytes(const uint64_t* values, uint8_t* out, uint32_t count, cudaStream_t stream) {
    uint32_t grid = div_up(count, BLOCK);
    grid = std::min(grid, 4096u);
    encode_to_bytes_kernel<<<grid, BLOCK, 0, stream>>>(values, out, count);
    CUDA_CHECK(cudaGetLastError());
}

void launch_sha256_hash_many(const uint8_t* input, uint8_t* output,
                             uint32_t message_size, uint32_t count, cudaStream_t stream) {
    uint32_t grid = div_up(count, BLOCK);
    grid = std::min(grid, 4096u);
    sha256_hash_many_kernel<<<grid, BLOCK, 0, stream>>>(input, output, message_size, count);
    CUDA_CHECK(cudaGetLastError());
}

void launch_blake3_hash_many(const uint8_t* input, uint8_t* output,
                             uint32_t message_size, uint32_t count, cudaStream_t stream) {
    uint32_t grid = div_up(count, BLOCK);
    grid = std::min(grid, 4096u);
    blake3_hash_many_kernel<<<grid, BLOCK, 0, stream>>>(input, output, message_size, count);
    CUDA_CHECK(cudaGetLastError());
}

//在CPU端分批启动CUDA kernel,让GPU对很多行Goldilocks数据做Blake3哈希，每一行输出32字节哈希值
//对应commit_leaves
void launch_blake3_hash_goldilocks_rows(const uint64_t* input, uint8_t* output,
                                        uint32_t row_elements, uint32_t count,
                                        cudaStream_t stream) {
    static constexpr uint32_t CHUNK = 65536;
    for (uint32_t base = 0; base < count; base += CHUNK) {
        const uint32_t chunk = std::min(CHUNK, count - base);
        uint32_t grid = div_up(chunk, BLOCK);
        grid = std::min(grid, 256u);
        blake3_hash_goldilocks_rows_kernel<<<grid, BLOCK, 0, stream>>>(
            input + static_cast<uint64_t>(base) * row_elements,
            output + static_cast<uint64_t>(base) * 32u,
            row_elements, chunk);
        CUDA_CHECK(cudaGetLastError());
    }
}

void launch_gather_hashes(const uint8_t* nodes, const uint64_t* node_indices,
                          uint8_t* out, uint32_t count, cudaStream_t stream) {
    if (count == 0) return;
    uint32_t grid = div_up(count, BLOCK);
    grid = std::min(grid, 4096u);
    gather_hashes_kernel<<<grid, BLOCK, 0, stream>>>(nodes, node_indices, out, count);
    CUDA_CHECK(cudaGetLastError());
}

void launch_encode_ext2_to_bytes(const uint64_t* c0, const uint64_t* c1,
                                  uint8_t* out, uint32_t count,
                                  cudaStream_t stream) {
    uint32_t grid = div_up(count, BLOCK);
    grid = std::min(grid, 4096u);
    encode_ext2_to_bytes_kernel<<<grid, BLOCK, 0, stream>>>(c0, c1, out, count);
    CUDA_CHECK(cudaGetLastError());
}

//启动一个CUDA Kernel ,把GoldilocksExt的三个分量c0/c1/c2编码成字节,写到out
void launch_encode_ext3_to_bytes(const uint64_t* c0, const uint64_t* c1,
                                  const uint64_t* c2, uint8_t* out, uint32_t count,
                                  cudaStream_t stream) {
    uint32_t grid = div_up(count, BLOCK); //计算grid维度
    grid = std::min(grid, 4096u);
    encode_ext3_to_bytes_kernel<<<grid, BLOCK, 0, stream>>>(c0, c1, c2, out, count);
    CUDA_CHECK(cudaGetLastError());
}

} // namespace whir::cuda
