#pragma once

// ============================================================================
// parameters.hpp — WHIR 协议全局配置
//
// ProtocolParameters 捕获决定协议行为的高层选择:
//   - 安全级别 (位)
//   - 码率与折叠策略
//   - 哈希函数选择
//   - PoW 难度预算
//
// 这些参数在 prover 和 verifier 间共享, 并序列化到 DomainSeparator
// 以将 transcript 绑定到特定协议配置。
//
// 对应 Rust: src/parameters.rs
// ============================================================================

#include "engines.hpp"

#include <cstddef>
#include <ostream>

namespace whir {

struct ProtocolParameters {
    bool unique_decoding = false;            // 唯一译码 vs 列表译码模式
    std::size_t starting_log_inv_rate = 0;   // 初始码的 log2(1/rate)
    std::size_t initial_folding_factor = 0;  // 第 0 轮的折叠因子
    std::size_t folding_factor = 0;          // 后续轮次的折叠因子
    std::size_t security_level = 0;          // 目标安全级别 (位)
    std::size_t pow_bits = 0;                // PoW 最大难度 (位)
    std::size_t batch_size = 0;              // 批量承诺中的向量数
    EngineId hash_id = ENGINE_ID_NONE;       // 哈希函数标识符

    friend bool operator==(const ProtocolParameters&, const ProtocolParameters&) = default;

    friend std::ostream& operator<<(std::ostream& os, const ProtocolParameters& p) {
        os << "Targeting " << p.security_level
           << "-bits of security with " << p.pow_bits
           << "-bits of PoW using "
           << (p.unique_decoding ? "unique" : "list")
           << " decoding\n";
        os << "Starting rate: 2^-" << p.starting_log_inv_rate
           << ", initial_folding_factor: " << p.initial_folding_factor
           << ", folding_factor: " << p.folding_factor
           << "\n";
        return os;
    }
};

} // namespace whir
