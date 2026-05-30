#pragma once

// ============================================================================
// hash_engine.hpp — 哈希引擎抽象层
//
// 定义 Hash（32 字节输出）类型和 HashEngine 基类。
// 所有哈希后端（SHA-256、BLAKE3、Copy）继承自 HashEngine
// 并实现 hash_many() 用于批量哈希。
//
// 各后端的 supports_size 约束:
//   BLAKE3 : size 必须是 64 的倍数，且 <= 1024
//   SHA-256: 任意 size
//   Copy   : size <= 32
//
// 继承自 Engine（engines.hpp）。Rust 侧使用 trait + dyn HashEngine；
// C++ 侧使用虚函数分派。EngineId 由 SHA3-256(b"whir::hash" || engine_name)
// 的前 32 字节计算得出，作为常量硬编码。
//
// 对应 Rust 文件: src/hash/mod.rs
// ============================================================================

#include "../engines.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace whir::hash {

// 32 字节定长哈希输出，与 sha2::Sha256 / blake3::Hash 输出长度一致。
using Hash = std::array<std::uint8_t, 32>;

// 所有哈希引擎的基类，在 Engine 之上增加哈希专用接口。
class HashEngine : public ::whir::Engine {
public:
    // 返回人类可读的引擎名称，用于诊断输出（不属于协议内容，EngineId 才是）。
    virtual std::string_view name() const = 0;

    // 判断后端是否支持对 `size` 字节的消息进行哈希。
    virtual bool supports_size(std::size_t size) const = 0;

    // 单线程场景下的推荐批量大小。SIMD 引擎返回较大值以充分利用向量化。
    virtual std::size_t preferred_batch_size() const { return 1; }

    // 批量哈希：对 output.size() 条独立消息分别计算摘要，每条消息长 size 字节。
    // 输入为连续平铺缓冲区，要求 input.size() == size * output.size()。
    // 输出写入 output[i]，每个元素为 32 字节摘要。
    virtual void hash_many(
        std::size_t size,
        std::span<const std::uint8_t> input,
        std::span<Hash> output) const = 0;
};

} // namespace whir::hash
