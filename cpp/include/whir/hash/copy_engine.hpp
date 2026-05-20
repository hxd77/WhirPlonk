#pragma once

// ============================================================================
// copy_engine.hpp — 恒等（拷贝）哈希引擎
//
// 不执行任何密码学哈希运算。将输入（最多 32 字节）直接拷贝到 32 字节的
// Hash 输出中，剩余字节以零填充。
//
// 设计用途:
//   - 单元测试：确定性的占位引擎，输出可预期
//   - 边界场景：当 message_size <= 32 时，可用 COPY 替代真实哈希
//     （输出 = 输入 || 零填充）
//
// 约束:
//   supports_size: size <= 32（受 32 字节 Hash 类型限制）
//   无 SIMD 批量路径；每条消息使用 memcpy 逐条处理。
//
// 对应 Rust 文件: src/hash/copy_engine.rs
// EngineId: SHA3-256(b"whir::hash" || b"copy") 的前 32 字节
// ============================================================================

#include "hash_engine.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace whir::hash {

// 与 Rust 实现一致的硬编码 EngineId。
inline constexpr ::whir::EngineId ENGINE_ID_COPY{std::array<std::uint8_t, 32>{
    0x09, 0x45, 0x90, 0x20, 0xf4, 0x51, 0x87, 0x4a,
    0x1b, 0x39, 0x98, 0x19, 0xd0, 0x79, 0x63, 0x2c,
    0xc0, 0xf9, 0x26, 0x3b, 0x14, 0x86, 0xc4, 0x23,
    0x17, 0x3c, 0x6e, 0x15, 0xd8, 0xe2, 0xd6, 0x1d,
}};

class Copy final : public HashEngine {
public:
    Copy() = default;

    // -- HashEngine 接口实现 --
    ::whir::EngineId engine_id() const override { return ENGINE_ID_COPY; }
    std::string_view name() const override { return "copy"; }

    // 输入长度不得超过 32 字节（Hash 输出上限）。
    bool supports_size(std::size_t size) const override { return size <= 32; }
    std::size_t preferred_batch_size() const override { return 1; }

    // 恒等哈希：将每条消息拷贝到输出 Hash 中，尾部以零填充。
    // 当 size == 0 时，输出全零。
    void hash_many(
        std::size_t size,
        std::span<const std::uint8_t> input,
        std::span<Hash> output) const override
    {
        assert(size <= 32 && "Copy engine only supports sizes up to 32 bytes");
        assert(input.size() == size * output.size());

        // 零长度消息产生全零哈希。
        if (size == 0) {
            for (auto& h : output) h.fill(0);
            return;
        }

        // 逐条拷贝消息切片；默认初始化的 Hash 已自带零填充。
        for (std::size_t i = 0; i < output.size(); ++i) {
            Hash h{};
            std::memcpy(h.data(), input.data() + i * size, size);
            output[i] = h;
        }
    }
};

} // namespace whir::hash
