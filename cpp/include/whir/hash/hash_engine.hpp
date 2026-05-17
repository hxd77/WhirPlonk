#pragma once

// ===========================================================================
// hash_engine.hpp — 哈希引擎抽象层
//Hash/HashEngine的用途、接口说明、继承关系图、EngineId生成规则
// 对应 WHIR 中的 src/hash/mod.rs。
//
// 定义了两个核心类型:
//   1. Hash              — 32 字节固定大小哈希值 (std::array<uint8_t, 32>)
//   2. HashEngine        — 所有哈希引擎的抽象基类
//
// HashEngine 接口:
//   name()                    — 引擎名称字符串 (如 "Sha2", "Blake3")
//   supports_size(size)       — 是否支持给定消息长度 (字节)
//                                BLAKE3 要求 size 是 64 的倍数且 ≤ 1024
//                                SHA-256 支持任意 size
//                                Copy 只支持 ≤ 32
//   preferred_batch_size()    — 最优批处理大小 (默认 1, SIMD 引擎可能更大)
//   hash_many(size, in, out)  — 批量哈希:
//       input 是 out.size() 个长度为 size 的连续消息拼起来的扁平 buffer
//       对每个消息独立哈希，结果写入 out[i]
//
// 继承关系:
//   Engine (engines.hpp)
//     └── HashEngine (本文件)
//           ├── Sha2   (sha2_engine.hpp)
//           ├── Blake3 (blake3_engine.hpp)
//           └── Copy   (copy_engine.hpp)
//
// Rust 端用 trait + dyn HashEngine 实现动态派发，C++ 用虚函数。
// EngineId 由 SHA3-256(b"whir::hash" + engine_name) 生成并硬编码为常量。
// ===========================================================================

#include "../engines.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace whir::hash {

// ---- Hash: 32 字节哈希值 ----
// 与 Rust 端 sha2::Sha256 / blake3::Hash 的输出长度一致。
using Hash = std::array<std::uint8_t, 32>;

// ---- HashEngine: 哈希引擎抽象基类 ----
// 继承自 Engine，增加了哈希特有的接口。
class HashEngine : public ::whir::Engine {
public:
    /// 引擎名称，用于调试和日志 (不参与协议，EngineId 才是协议标识)
    virtual std::string_view name() const = 0;

    /// 检查是否支持给定的消息字节长度
    virtual bool supports_size(std::size_t size) const = 0;

    /// 单线程最优批处理大小。不支持 SIMD 的引擎默认为 1。
    virtual std::size_t preferred_batch_size() const { return 1; }

    /// 批量哈希: 把 input 切成 output.size() 段，每段 size 字节，分别哈希。
    /// input.size() 必须 == size * output.size()
    virtual void hash_many(
        std::size_t size,
        std::span<const std::uint8_t> input,
        std::span<Hash> output) const = 0;
};

} // namespace whir::hash
