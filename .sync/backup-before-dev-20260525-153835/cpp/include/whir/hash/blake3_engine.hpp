#pragma once

// ============================================================================
// blake3_engine.hpp — BLAKE3 哈希引擎
//
// 封装 BLAKE3 官方 C 参考实现（cpp/third_party/blake3/, v1.5.4）。
// BLAKE3 采用 Merkle 树内部结构，可通过 blake3_hash_many() 利用 SIMD 加速。
// 当 OpenMP 可用时，独立批次将并行处理。
//
// 约束（与 Rust 快速路径一致）:
//   supports_size       : size 必须是 BLAKE3_BLOCK_LEN（64）的倍数，
//                         且 <= BLAKE3_CHUNK_LEN（1024）
//   preferred_batch_size: blake3_simd_degree()（平台相关）
//   size == 0           : 返回 BLAKE3 空消息常量摘要
//                         （af1349b9...41f3262）
//
// 对于超出快速路径约束的 size，回退到逐条使用
// blake3_hasher_init/update/finalize 的方式处理。
//
// 对应 Rust 文件: src/hash/blake3_engine.rs
// EngineId: SHA3-256(b"whir::hash" || b"blake3") 的前 32 字节
// ============================================================================

#include "../engines.hpp"
#include "hash_counter.hpp"
#include "hash_engine.hpp"

extern "C" {
#include "blake3.h"  // blake3_hasher / blake3_hasher_init / _update / _finalize

void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t *out);
size_t blake3_simd_degree(void);
}

#include <array>
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <string_view>

namespace whir::hash {

// 与 Rust 实现一致的硬编码 EngineId。
inline constexpr ::whir::EngineId ENGINE_ID_BLAKE3{std::array<std::uint8_t, 32>{
    0x03, 0xe0, 0x17, 0x49, 0xeb, 0xcc, 0x04, 0x77,
    0x92, 0x42, 0x54, 0xeb, 0x48, 0x20, 0x66, 0xb8,
    0x64, 0xa8, 0xdd, 0x4d, 0x77, 0x25, 0x24, 0x64,
    0xca, 0x6f, 0x5b, 0x6f, 0x5c, 0xc0, 0x5b, 0x4c,
}};

// BLAKE3 初始向量（与 BLAKE2 IV 相同，遵从规范定义）。
inline constexpr std::array<std::uint32_t, 8> BLAKE3_IV{
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

// 传递给 blake3_hash_many 的标志位，用于标记 chunk 边界。
inline constexpr std::uint8_t BLAKE3_CHUNK_START = 1u << 0;
inline constexpr std::uint8_t BLAKE3_CHUNK_END_ROOT = (1u << 1) | (1u << 3);

class Blake3 final : public HashEngine {
public:
    Blake3() = default;

    // -- HashEngine 接口实现 --
    whir::EngineId engine_id() const override { return ENGINE_ID_BLAKE3; }
    std::string_view name() const override { return "Blake3"; }

    // 快速路径要求 size 对齐到 BLAKE3_BLOCK_LEN（64）且不超过 BLAKE3_CHUNK_LEN（1024）。
    bool supports_size(std::size_t size) const override {
        return (size % 64 == 0) && size <= 1024;
    }

    // 返回 BLAKE3 库报告的 SIMD 宽度。
    std::size_t preferred_batch_size() const override {
        return ::blake3_simd_degree();
    }

    // 逐条独立哈希。两条代码路径：
    //   1. 快速路径（supports_size 为 true）：使用 blake3_hash_many，
    //      批次间可通过 OpenMP 并行。
    //   2. 回退路径：逐条使用 blake3_hasher_init/update/finalize，
    //      同样在 OpenMP 可用时并行化。
    void hash_many(
        std::size_t size,
        std::span<const std::uint8_t> input,
        std::span<Hash> output) const override
    {
        assert(input.size() == size * output.size());

        // 空消息：直接返回 BLAKE3 空输入的常量摘要。
        if (size == 0) {
            constexpr Hash EMPTY_HASH = {
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
                0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
                0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
                0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
            };
            const std::size_t count = output.size();
#ifdef _OPENMP
            #pragma omp parallel for if(count >= 1024)
#endif
            for (std::ptrdiff_t i = 0; i < static_cast<std::ptrdiff_t>(count); ++i) {
                output[static_cast<std::size_t>(i)] = EMPTY_HASH;
            }
            return;
        }

        const std::size_t count = output.size();

        // 快速路径：使用 blake3_hash_many 进行 SIMD 批量哈希。
        if (supports_size(size)) {
            const std::size_t blocks = size / 64;
            if (count <= 64) {
                std::array<const std::uint8_t*, 64> ptrs{};
                for (std::size_t i = 0; i < count; ++i) {
                    ptrs[i] = input.data() + i * size;
                }
                ::blake3_hash_many(
                    ptrs.data(), count, blocks, BLAKE3_IV.data(), 0,
                    false, 0, BLAKE3_CHUNK_START, BLAKE3_CHUNK_END_ROOT,
                    reinterpret_cast<std::uint8_t*>(output.data()));
                hash_counter().add(output.size());
                return;
            }

            const std::size_t batch_size = std::max<std::size_t>(::blake3_simd_degree() * 256, 256);
            const std::size_t num_batches = (count + batch_size - 1) / batch_size;

            // 为每个批次构建指针数组，分派给 blake3_hash_many。
#ifdef _OPENMP
            if (num_batches >= 2) {
                #pragma omp parallel
                {
                    std::vector<const std::uint8_t*> ptrs;
                    ptrs.reserve(batch_size);

                    #pragma omp for
                    for (std::ptrdiff_t pb = 0; pb < static_cast<std::ptrdiff_t>(num_batches); ++pb) {
                        const std::size_t batch = static_cast<std::size_t>(pb);
                        const std::size_t begin = batch * batch_size;
                        const std::size_t n = std::min(batch_size, count - begin);

                        ptrs.resize(n);
                        for (std::size_t j = 0; j < n; ++j) {
                            ptrs[j] = input.data() + (begin + j) * size;
                        }

                        ::blake3_hash_many(
                            ptrs.data(), n, blocks, BLAKE3_IV.data(), 0,
                            false, 0, BLAKE3_CHUNK_START, BLAKE3_CHUNK_END_ROOT,
                            reinterpret_cast<std::uint8_t*>(output.data() + begin));
                    }
                }
            } else
#endif
            {
                std::vector<const std::uint8_t*> ptrs;
                ptrs.reserve(batch_size);
                for (std::size_t batch = 0; batch < num_batches; ++batch) {
                    const std::size_t begin = batch * batch_size;
                    const std::size_t n = std::min(batch_size, count - begin);

                    ptrs.resize(n);
                    for (std::size_t j = 0; j < n; ++j) {
                        ptrs[j] = input.data() + (begin + j) * size;
                    }

                    ::blake3_hash_many(
                        ptrs.data(), n, blocks, BLAKE3_IV.data(), 0,
                        false, 0, BLAKE3_CHUNK_START, BLAKE3_CHUNK_END_ROOT,
                        reinterpret_cast<std::uint8_t*>(output.data() + begin));
                }
            }

            hash_counter().add(output.size());
            return;
        }

        // 回退路径：超出快速路径约束的 size，逐条哈希。
#ifdef _OPENMP
        #pragma omp parallel for if(count >= 1024)
#endif
        for (std::ptrdiff_t pi = 0; pi < static_cast<std::ptrdiff_t>(count); ++pi) {
            const std::size_t i = static_cast<std::size_t>(pi);
            ::blake3_hasher hasher;
            ::blake3_hasher_init(&hasher);
            ::blake3_hasher_update(&hasher, input.data() + i * size, size);
            ::blake3_hasher_finalize(&hasher, output[i].data(), output[i].size());
        }

        hash_counter().add(output.size());
    }
};

} // namespace whir::hash
