#pragma once

// ===========================================================================
// copy_engine.hpp — "恒等映射" 哈希引擎 (不做实际哈希)
// 对应 WHIR 中的 src/hash/copy_engine.rs。
//
// 不做任何哈希计算，直接把 ≤ 32 字节的输入原样复制到输出 (尾部补零)。
//
// 用途:
//   - 单元测试: 作为确定性占位引擎，便于构造已知输出的测试用例
//   - 边界情况: message_size ≤ 32 时可以用 COPY 替代真实哈希(输出 = 输入补零)
//
// 限制:
//   - supports_size: 只支持 size ≤ 32 (因为 Hash 就是 32 字节)
//   - 效率: 无批处理，直接 memcpy
//
// EngineId: SHA3-256(b"whir::hash" + b"copy") 的前 32 字节
// ===========================================================================

#include "hash_engine.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace whir::hash {

// Rust 端硬编码的 Copy EngineId
inline constexpr ::whir::EngineId ENGINE_ID_COPY{std::array<std::uint8_t, 32>{
    0x09, 0x45, 0x90, 0x20, 0xf4, 0x51, 0x87, 0x4a,
    0x1b, 0x39, 0x98, 0x19, 0xd0, 0x79, 0x63, 0x2c,
    0xc0, 0xf9, 0x26, 0x3b, 0x14, 0x86, 0xc4, 0x23,
    0x17, 0x3c, 0x6e, 0x15, 0xd8, 0xe2, 0xd6, 0x1d,
}};

class Copy final : public HashEngine {
public:
    Copy() = default;

    // ---- HashEngine 接口实现 ----
    ::whir::EngineId engine_id() const override { return ENGINE_ID_COPY; }
    std::string_view name() const override { return "copy"; }

    // 只能处理 ≤ 32 字节的输入 (因为输出只有 32 字节)
    bool supports_size(std::size_t size) const override { return size <= 32; }
    std::size_t preferred_batch_size() const override { return 1; }

    /// "恒等" 批量哈希:
    ///   size=0 → output[i] 全部填零
    ///   size>0 → output[i] = input[i*size..(i+1)*size] 原样复制 (尾部补零)
    void hash_many(
        std::size_t size,
        std::span<const std::uint8_t> input,
        std::span<Hash> output) const override //子类重写父类的虚函数
    {
        assert(size <= 32 && "Copy engine only supports sizes up to 32 bytes");
        assert(input.size() == size * output.size());

        if (size == 0) {
            // 零长度输入 → 全部填零
            for (auto& h : output) h.fill(0);
            return;
        }

        for (std::size_t i = 0; i < output.size(); ++i) {
            Hash h{};  // 默认填零
            std::memcpy(h.data(), input.data() + i * size, size);  // 复制输入到h.data()
            output[i] = h;  // 多余字节保持为零
        }
    }
};

} // namespace whir::hash
