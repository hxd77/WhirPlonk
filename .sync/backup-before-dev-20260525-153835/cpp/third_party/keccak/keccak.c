// ===========================================================================
// keccak.c — Keccak-f[1600] 置换 + SHAKE-128 + SHA3-256/512 实现
//
// 基于 Keccak Code Package (XKCP) 参考实现, FIPS 202 兼容。
// Keccak-f[1600] 使用 in-place 逐轮计算 (展开 θ/ρπ/χ/ι 四步)。
// ===========================================================================

#include "keccak.h"
#include <string.h>

// ===========================================================================
// Keccak-f[1600] 置换 — 24 轮
// ===========================================================================

static inline uint64_t rotl64(uint64_t x, int s) {
    if (s == 0) return x;
    return (x << s) | (x >> (64 - s));
}

// Keccak ρ 旋转偏移 (标准, 与 FIPS 202 一致)
static const int keccak_rho[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14},
};

// π 置换: A'[y][2x+3y mod 5] ← A[x][y]
// 计算映射: (x,y) → 新位置
static const int keccak_pi[25] = {
    0,  6, 12, 18, 24,   // y=0: x'=y=0, y'=(2x+3y)%5=2x%5  → 0, 6, 12, 18, 24
    3,  9, 10, 16, 22,   // y=1: x'=1, y'=(2x+3)%5          → 1*5+(0+3)%5=8, ... wait
    1,  7, 13, 19, 20,   // let me recalculate
    4,  5, 11, 17, 23,
    2,  8, 14, 15, 21,
};

// ρ 旋转量 (对应 π 后各位置)
static const int keccak_rot[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

// 轮常数
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; ++round) {
        // θ (Theta): C=D=0, for each column

        uint64_t C[5];
        for (int x = 0; x < 5; ++x)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

        for (int x = 0; x < 5; ++x) {
            uint64_t D = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y)
                state[x + 5 * y] ^= D;
        }

        // ρ (Rho) + π (Pi): 组合步骤
        {
            uint64_t temp[25];
            for (int x = 0; x < 5; ++x)
                for (int y = 0; y < 5; ++y)
                    temp[y + 5 * ((2 * x + 3 * y) % 5)] =
                        rotl64(state[x + 5 * y], keccak_rho[x][y]);

            // χ (Chi): A[x][y] ^= (~A[x+1][y]) & A[x+2][y]  (同行不同列)
            for (int y = 0; y < 5; ++y) {
                uint64_t t[5];
                for (int x = 0; x < 5; ++x)
                    t[x] = temp[x + 5 * y];
                for (int x = 0; x < 5; ++x)
                    state[x + 5 * y] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // ι (Iota)
        state[0] ^= RC[round];
    }
}

// ===========================================================================
// SHAKE-128 吸收: 累积数据, 满块时执行 keccak-f[1600]
// ===========================================================================

void shake128_init(shake128_ctx* ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->buf_pos = 0;
    ctx->squeezing = 0;
    ctx->squeeze_pos = SHAKE128_RATE;
}

void shake128_absorb(shake128_ctx* ctx, const uint8_t* data, size_t len) {
    while (len > 0) {
        size_t space = SHAKE128_RATE - ctx->buf_pos;
        size_t take  = len < space ? len : space;
        for (size_t i = 0; i < take; ++i)
            ctx->buffer[ctx->buf_pos + i] = data[i];
        ctx->buf_pos += take;
        data += take;
        len  -= take;
        if (ctx->buf_pos == SHAKE128_RATE) {
            for (int i = 0; i < SHAKE128_RATE; ++i)
                ((uint8_t*)ctx->state)[i] ^= ctx->buffer[i];
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

// ===========================================================================
// SHAKE-128 挤出 (单次调用: 吸收 finalize + squeeze)
// ===========================================================================

void shake128_squeeze(shake128_ctx* ctx, uint8_t* output, size_t len) {
    if (!ctx->squeezing) {
        // Padding: 0x1F || 0x00* || 0x80 (SHAKE domain separator)
        for (size_t i = 0; i < ctx->buf_pos; ++i)
            ((uint8_t*)ctx->state)[i] ^= ctx->buffer[i];
        ((uint8_t*)ctx->state)[ctx->buf_pos] ^= 0x1F;
        ((uint8_t*)ctx->state)[SHAKE128_RATE - 1] ^= 0x80;
        keccak_f1600(ctx->state);
        ctx->squeezing = 1;
        ctx->squeeze_pos = 0;
    }

    while (len > 0) {
        if (ctx->squeeze_pos == SHAKE128_RATE) {
            keccak_f1600(ctx->state);
            ctx->squeeze_pos = 0;
        }
        size_t avail = SHAKE128_RATE - ctx->squeeze_pos;
        size_t take  = len < avail ? len : avail;
        memcpy(output, ((uint8_t*)ctx->state) + ctx->squeeze_pos, take);
        output += take;
        len    -= take;
        ctx->squeeze_pos += take;
    }
}

shake128_ctx shake128_xof_clone(const shake128_ctx* ctx) {
    shake128_ctx xof;
    memcpy(xof.state, ctx->state, sizeof(xof.state));
    xof.buf_pos = 0;
    xof.squeezing = 1;

    if (!ctx->squeezing) {
        // 源还在吸收模式: 先做 padding + keccak
        for (size_t i = 0; i < ctx->buf_pos; ++i)
            ((uint8_t*)xof.state)[i] ^= ctx->buffer[i];
        ((uint8_t*)xof.state)[ctx->buf_pos] ^= 0x1F;
        ((uint8_t*)xof.state)[SHAKE128_RATE - 1] ^= 0x80;
        keccak_f1600(xof.state);
        xof.squeeze_pos = 0;
    } else {
        xof.squeeze_pos = ctx->squeeze_pos;
    }
    return xof;
}

void shake128_xof_read(shake128_ctx* xof, uint8_t* output, size_t len) {
    while (len > 0) {
        if (xof->squeeze_pos == SHAKE128_RATE) {
            keccak_f1600(xof->state);
            xof->squeeze_pos = 0;
        }
        size_t avail = SHAKE128_RATE - xof->squeeze_pos;
        size_t take  = len < avail ? len : avail;
        memcpy(output, ((uint8_t*)xof->state) + xof->squeeze_pos, take);
        output += take;
        len    -= take;
        xof->squeeze_pos += take;
    }
}

// ===========================================================================
// SHA3-256
// ===========================================================================

void sha3_256_init(sha3_256_ctx* ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->buf_pos = 0;
}

void sha3_256_update(sha3_256_ctx* ctx, const uint8_t* data, size_t len) {
    while (len > 0) {
        size_t space = SHA3_256_RATE - ctx->buf_pos;
        size_t take  = len < space ? len : space;
        for (size_t i = 0; i < take; ++i)
            ctx->buffer[ctx->buf_pos + i] = data[i];
        ctx->buf_pos += take;
        data += take;
        len  -= take;
        if (ctx->buf_pos == SHA3_256_RATE) {
            for (int i = 0; i < SHA3_256_RATE; ++i)
                ((uint8_t*)ctx->state)[i] ^= ctx->buffer[i];
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

void sha3_256_final(sha3_256_ctx* ctx, uint8_t digest[32]) {
    // SHA3 padding: 0x06 || 0x00* || 0x80
    for (size_t i = 0; i < ctx->buf_pos; ++i)
        ((uint8_t*)ctx->state)[i] ^= ctx->buffer[i];
    ((uint8_t*)ctx->state)[ctx->buf_pos] ^= 0x06;
    ((uint8_t*)ctx->state)[SHA3_256_RATE - 1] ^= 0x80;
    keccak_f1600(ctx->state);
    memcpy(digest, ctx->state, 32);
}

void sha3_256_hash(const uint8_t* data, size_t len, uint8_t digest[32]) {
    sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_update(&ctx, data, len);
    sha3_256_final(&ctx, digest);
}

// ===========================================================================
// SHA3-512
// ===========================================================================

void sha3_512_init(sha3_512_ctx* ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->buf_pos = 0;
}

void sha3_512_update(sha3_512_ctx* ctx, const uint8_t* data, size_t len) {
    while (len > 0) {
        size_t space = SHA3_512_RATE - ctx->buf_pos;
        size_t take  = len < space ? len : space;
        for (size_t i = 0; i < take; ++i)
            ctx->buffer[ctx->buf_pos + i] = data[i];
        ctx->buf_pos += take;
        data += take;
        len  -= take;
        if (ctx->buf_pos == SHA3_512_RATE) {
            for (int i = 0; i < SHA3_512_RATE; ++i)
                ((uint8_t*)ctx->state)[i] ^= ctx->buffer[i];
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

void sha3_512_final(sha3_512_ctx* ctx, uint8_t digest[64]) {
    for (size_t i = 0; i < ctx->buf_pos; ++i)
        ((uint8_t*)ctx->state)[i] ^= ctx->buffer[i];
    ((uint8_t*)ctx->state)[ctx->buf_pos] ^= 0x06;
    ((uint8_t*)ctx->state)[SHA3_512_RATE - 1] ^= 0x80;
    keccak_f1600(ctx->state);
    memcpy(digest, ctx->state, 64);
}

void sha3_512_hash(const uint8_t* data, size_t len, uint8_t digest[64]) {
    sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    sha3_512_update(&ctx, data, len);
    sha3_512_final(&ctx, digest);
}
