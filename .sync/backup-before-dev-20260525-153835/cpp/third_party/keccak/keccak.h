// ===========================================================================
// keccak.h — Keccak-f[1600] 置换 + SHAKE-128 + SHA3-256/512
//
// FIPS 202 兼容实现, 用于替换 SHA-256 以匹配 Rust 端 spongefish 的 StdHash (SHAKE-128)。
//
// SHAKE-128 (XOF):        rate=168B (1344bit), capacity=32B (256bit), suffix=1111
// SHA3-256 (hash):        rate=136B (1088bit), capacity=64B (512bit),  suffix=01
// SHA3-512 (hash):        rate=72B  (576bit),  capacity=128B(1024bit), suffix=01
//
// 用法:
//   // SHAKE-128 XOF
//   shake128_ctx ctx;
//   shake128_init(&ctx);
//   shake128_absorb(&ctx, data, len);        // 吸收数据 (可多次调用)
//   shake128_squeeze(&ctx, out, out_len);    // 挤出数据 (可多次调用)
//   shake128_xof_init(&ctx);                 // 进入挤出阶段 (clone + finalize)
//   shake128_xof_read(&ctx, out, out_len);   // 从 XOF reader 读取
//
//   // SHA3-256
//   sha3_256_ctx ctx;
//   sha3_256_init(&ctx);
//   sha3_256_update(&ctx, data, len);
//   sha3_256_final(&ctx, out_32bytes);
//
//   // SHA3-512
//   sha3_512(&ctx, data, len, out_64bytes);  // 一体化
// ===========================================================================
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ===========================================================================
// SHAKE-128 (Extendable Output Function)
// ===========================================================================

#define SHAKE128_RATE      168   // rate in bytes (1344 bits)
#define SHAKE128_CAPACITY  32    // capacity in bytes (256 bits)
#define SHAKE128_STATE_SIZE 25   // 25 × uint64_t = 200 bytes

typedef struct {
    uint64_t state[SHAKE128_STATE_SIZE]; // Keccak state (200 bytes)
    size_t   buf_pos;                    // write position in rate segment
    uint8_t  buffer[SHAKE128_RATE];      // input buffer
    int      squeezing;                  // 0=absorbing, 1=squeezing
    size_t   squeeze_pos;                // read position for squeeze
} shake128_ctx;

void shake128_init(shake128_ctx* ctx);
void shake128_absorb(shake128_ctx* ctx, const uint8_t* data, size_t len);
void shake128_squeeze(shake128_ctx* ctx, uint8_t* output, size_t len);

// XOF reader: clone + finalize, then read (对应 Rust 的 finalize_xof + read)
shake128_ctx shake128_xof_clone(const shake128_ctx* ctx);
void shake128_xof_read(shake128_ctx* xof, uint8_t* output, size_t len);

// ===========================================================================
// SHA3-256 (32-byte hash output)
// ===========================================================================

#define SHA3_256_RATE      136
#define SHA3_256_CAPACITY  64
#define SHA3_256_DIGEST    32

typedef struct {
    uint64_t state[25];
    size_t   buf_pos;
    uint8_t  buffer[SHA3_256_RATE];
} sha3_256_ctx;

void sha3_256_init(sha3_256_ctx* ctx);
void sha3_256_update(sha3_256_ctx* ctx, const uint8_t* data, size_t len);
void sha3_256_final(sha3_256_ctx* ctx, uint8_t digest[SHA3_256_DIGEST]);

// 一体化
void sha3_256_hash(const uint8_t* data, size_t len, uint8_t digest[32]);

// ===========================================================================
// SHA3-512 (64-byte hash output)
// ===========================================================================

#define SHA3_512_RATE      72
#define SHA3_512_CAPACITY  128
#define SHA3_512_DIGEST    64

typedef struct {
    uint64_t state[25];
    size_t   buf_pos;
    uint8_t  buffer[SHA3_512_RATE];
} sha3_512_ctx;

void sha3_512_init(sha3_512_ctx* ctx);
void sha3_512_update(sha3_512_ctx* ctx, const uint8_t* data, size_t len);
void sha3_512_final(sha3_512_ctx* ctx, uint8_t digest[SHA3_512_DIGEST]);

// 一体化
void sha3_512_hash(const uint8_t* data, size_t len, uint8_t digest[64]);

#ifdef __cplusplus
}
#endif
