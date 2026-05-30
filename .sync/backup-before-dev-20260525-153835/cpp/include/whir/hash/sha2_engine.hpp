#pragma once

// ============================================================================
// sha2_engine.hpp — SHA-256 哈希引擎
//
// 封装 Brad Conte 的公有领域 SHA-256 C 参考实现
// （cpp/third_party/sha256/）。SHA-256 完全确定性，输出与 Rust sha2 crate
// 逐字节一致。
//
// 属性:
//   supports_size       : 任意长度（无对齐要求）
//   preferred_batch_size: 1（纯 C 实现，无 SIMD 批量路径）
//   size == 0           : 返回 SHA-256("")（空字符串摘要）
//
// 构建说明：cpp/third_party/sha256/sha256.c 必须编译到同一翻译单元中
// （由 CMakeLists 处理）。
//
// 对应 Rust 文件: src/hash/digest_engine.rs（Sha2 变体）
// EngineId: SHA3-256(b"whir::hash" || b"sha2") 的前 32 字节
// ============================================================================

#include "../engines.hpp"
#include "hash_counter.hpp"
#include "hash_engine.hpp"

extern "C" {
#include "sha256.h"   // SHA256_CTX / sha256_init / sha256_update / sha256_final
}

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace whir::hash {

// 与 Rust 实现一致的硬编码 EngineId。
inline constexpr ::whir::EngineId ENGINE_ID_SHA2{std::array<std::uint8_t, 32>{
    0x01, 0x8e, 0xaa, 0x24, 0x7c, 0xb8, 0x95, 0x7a,
    0xb1, 0xe9, 0xfd, 0xac, 0x88, 0x54, 0x50, 0x40,
    0x3c, 0x5e, 0x7b, 0xda, 0x1a, 0xca, 0xaa, 0x50,
    0x4e, 0x4c, 0xc8, 0xf2, 0xf7, 0x6b, 0xb0, 0x76,
}};

class Sha2 final : public HashEngine {
public:
    Sha2() = default;

    // -- HashEngine 接口实现 --
    ::whir::EngineId engine_id() const override { return ENGINE_ID_SHA2; }
    std::string_view name() const override { return "Sha2"; }

    // SHA-256 接受任意长度消息。
    bool supports_size(std::size_t /*size*/) const override { return true; }

    // 纯 C 实现，无 SIMD；逐条处理。
    std::size_t preferred_batch_size() const override { return 1; }

    // 通过 C SHA-256 API 逐条独立哈希。
    // 对每个 i ∈ [0, output.size())：output[i] = SHA-256(input[i*size .. (i+1)*size])。
    void hash_many(
        std::size_t size,
        std::span<const std::uint8_t> input,
        std::span<Hash> output) const override
    {
        assert(input.size() == size * output.size());

        for (std::size_t i = 0; i < output.size(); ++i) {
            ::SHA256_CTX ctx;
            ::sha256_init(&ctx);
            if (size > 0) {
                ::sha256_update(&ctx, input.data() + i * size, size);
            }
            ::sha256_final(&ctx, output[i].data());
        }

        hash_counter().add(output.size());
    }
};

} // namespace whir::hash
