#pragma once

// ============================================================================
// proof_of_work.hpp — WHIR 轮次安全性的 PoW 谜题
//
// 在每个 sumcheck 轮次中插入基于哈希的 PoW，增加证明者的计算成本，
// 弥补逐轮安全性分析中的信息论缺口。
//
// 谜题定义:
//   输入布局（64 字节）:
//     [0..32)   challenge (32B)  — 从 transcript 挤压
//     [32..40)  nonce (8B, LE)   — 证明者找到的小整数
//     [40..64)  zeros (24B)      — 填充（对齐到哈希块大小）
//   hash(challenge||nonce_le||zeros)取哈希结果的前8字节,当作一个uint64_t数字
//   条件: LE_u64(hash(input)[0..8]) <= threshold
//
// 难度编码:
//   threshold(d) = ceil(2^(64 - d))
//   d = 0   -> threshold = UINT64_MAX（平凡）
//   d = 60  -> threshold = 2^4 = 16   （极难）
//
// 组件:
//   纯函数: threshold(), difficulty_of(), find_nonce(), check_nonce()
//   协议层: PowConfig，带 transcript 感知的 prove/verify
//
// 注意: find_nonce 使用批量哈希（preferred_batch_size）提高吞吐量，
//       但结果是全局最小有效 nonce（等价于顺序搜索）。
//
// 对应 Rust 文件: src/protocols/proof_of_work.rs
// 对应 C++ 文件:  hash/hash_engine.hpp (HashEngine)
// ============================================================================

#include "../bits.hpp"
#include "../hash/hash_engine.hpp"
#include "../transcript/transcript.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace whir::protocols::pow {

// ============================================================================
// 难度 <-> 阈值转换
// ============================================================================

/// 从难度比特计算阈值: threshold = ceil(2^(64 - difficulty))。
/// difficulty=0 时返回 UINT64_MAX（任意 nonce 均通过）。
inline std::uint64_t threshold(::whir::Bits difficulty) {
    const double d = static_cast<double>(difficulty);
    assert(d >= 0.0 && d <= 60.0);  // >60 比特计算上不可行
    const double t = std::ceil(std::exp2(64.0 - d));
    if (t >= static_cast<double>(UINT64_MAX)) return UINT64_MAX;
    return static_cast<std::uint64_t>(t);
}

/// threshold() 的逆运算: difficulty = 64 - log2(threshold)。
inline ::whir::Bits difficulty_of(std::uint64_t threshold) {
    return ::whir::Bits{64.0 - std::log2(static_cast<double>(threshold))};
}

// ============================================================================
// 纯哈希工具函数
// ============================================================================

/// 将哈希的前 8 字节解释为小端 u64。
inline std::uint64_t hash_to_u64_le(const ::whir::hash::Hash& h) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | static_cast<std::uint64_t>(h[i]);
    }
    return v;
}

// ============================================================================
// 纯 nonce 搜索（无 transcript 交互）
// ============================================================================

/// 找到满足 hash(challenge || nonce_le || zeros) <= threshold 的最小 nonce。
///
/// 使用批量哈希（batch = engine.preferred_batch_size()）提高吞吐量。
/// 结果等价于顺序搜索 — 全局最小有效 nonce。
/// 当 threshold == UINT64_MAX（零难度）时立即返回 0。
inline std::uint64_t find_nonce(
    const ::whir::hash::HashEngine& engine,
    const std::array<std::uint8_t, 32>& challenge,
    std::uint64_t threshold)
{
    if (threshold == UINT64_MAX) return 0;

    const std::size_t batch = engine.preferred_batch_size();

    // --- OpenMP 并行路径 ---
#ifdef _OPENMP
    const int num_threads = omp_get_max_threads();
    if (num_threads > 1) {
        std::atomic<std::uint64_t> global_min{std::numeric_limits<std::uint64_t>::max()};

        #pragma omp parallel
        {
            const int tid = omp_get_thread_num();
            const int actual_threads = omp_get_num_threads();
            const std::uint64_t stride =
                static_cast<std::uint64_t>(batch) * static_cast<std::uint64_t>(actual_threads);

            // 预填充 challenge 字节到每个 batch 槽位
            std::vector<std::uint8_t> inputs(64 * batch, 0);
            std::vector<::whir::hash::Hash> outputs(batch);
            for (std::size_t i = 0; i < batch; ++i) {
                std::memcpy(&inputs[64 * i], challenge.data(), 32);
            }

            // 每个线程搜索自己的跨步范围；如果其他线程找到更小的 nonce 则提前停止。
            for (std::uint64_t base = static_cast<std::uint64_t>(batch) * static_cast<std::uint64_t>(tid);
                 base < global_min.load(std::memory_order_relaxed);
                 base += stride) {
                for (std::size_t i = 0; i < batch; ++i) {
                    const std::uint64_t n = base + static_cast<std::uint64_t>(i);
                    for (int b = 0; b < 8; ++b) {
                        inputs[64 * i + 32 + b] =
                            static_cast<std::uint8_t>((n >> (8 * b)) & 0xFFu);
                    }
                }

                engine.hash_many(64,
                    std::span<const std::uint8_t>{inputs.data(), inputs.size()},
                    std::span<::whir::hash::Hash>{outputs.data(), outputs.size()});

                for (std::size_t i = 0; i < batch; ++i) {
                    if (hash_to_u64_le(outputs[i]) <= threshold) {
                        const std::uint64_t candidate = base + static_cast<std::uint64_t>(i);
                        std::uint64_t current = global_min.load(std::memory_order_relaxed);
                        while (candidate < current &&
                               !global_min.compare_exchange_weak(
                                   current, candidate,
                                   std::memory_order_seq_cst,
                                   std::memory_order_relaxed)) {
                        }
                        break;
                    }
                }
            }
        }

        const std::uint64_t nonce = global_min.load(std::memory_order_seq_cst);
        assert(nonce != std::numeric_limits<std::uint64_t>::max() &&
               "Proof of Work failed to solve.");
        return nonce;
    }
#endif

    // --- 顺序路径 ---
    std::vector<std::uint8_t> inputs(64 * batch, 0);
    std::vector<::whir::hash::Hash> outputs(batch);

    // 预填充 challenge（32 字节）到每个 batch 槽位
    for (std::size_t i = 0; i < batch; ++i) {
        std::memcpy(&inputs[64 * i], challenge.data(), 32);
    }

    // 以 batch 大小为步长扫描 nonce 空间
    for (std::uint64_t base = 0;; base += static_cast<std::uint64_t>(batch)) {
        // 为本 batch 写入 nonce（LE 编码）
        for (std::size_t i = 0; i < batch; ++i) {
            const std::uint64_t n = base + static_cast<std::uint64_t>(i);
            for (int b = 0; b < 8; ++b) {
                inputs[64 * i + 32 + b] = static_cast<std::uint8_t>((n >> (8 * b)) & 0xFFu);
            }
        }

        engine.hash_many(64,
            std::span<const std::uint8_t>{inputs.data(), inputs.size()},
            std::span<::whir::hash::Hash>{outputs.data(), outputs.size()});

        // 返回本 batch 中第一个满足阈值的 nonce
        for (std::size_t i = 0; i < batch; ++i) {
            if (hash_to_u64_le(outputs[i]) <= threshold) {
                return base + static_cast<std::uint64_t>(i);
            }
        }
    }
}

/// 验证单个 nonce: 重新计算哈希并与阈值比较。
/// 当 threshold == UINT64_MAX（零难度）时立即返回 true。
inline bool check_nonce(
    const ::whir::hash::HashEngine& engine,
    const std::array<std::uint8_t, 32>& challenge,
    std::uint64_t nonce,
    std::uint64_t threshold)
{
    if (threshold == UINT64_MAX) return true;

    // 构造 64 字节输入: challenge || nonce_le || zeros
    std::array<std::uint8_t, 64> input{};
    std::memcpy(input.data(), challenge.data(), 32);
    for (int b = 0; b < 8; ++b) {
        input[32 + b] = static_cast<std::uint8_t>((nonce >> (8 * b)) & 0xFFu);
    }
    // [40..64) 为零初始化

    ::whir::hash::Hash out{};
    engine.hash_many(64,
        std::span<const std::uint8_t>{input.data(), input.size()},
        std::span<::whir::hash::Hash>{&out, 1});
    return hash_to_u64_le(out) <= threshold;
}

// ============================================================================
// PowConfig — 带 transcript 交互的协议级 PoW
// ============================================================================

/// PoW 配置，带 transcript 感知的 prove/verify。
///
/// 对应 Rust: proof_of_work::Config
struct PowConfig {
    ::whir::EngineId hash_id;
    std::uint64_t threshold_val = UINT64_MAX;  // UINT64_MAX = 零难度

    ::whir::Bits difficulty() const { return difficulty_of(threshold_val); }

    // ---- prove: 挤压挑战，寻找 nonce，发送 nonce ----

    /// 使用显式引擎引用进行证明。
    template <typename Transcript>
    void prove(Transcript& prover_state,
               const ::whir::hash::HashEngine& engine) const
    {
        if (threshold_val == UINT64_MAX) return;  // 零难度 -> 跳过

        // 1. 从 transcript 挤压 32 字节挑战
        auto challenge = prover_state.template verifier_message<std::array<std::uint8_t, 32>>();

        // 2. 搜索有效 nonce
        std::uint64_t nonce = find_nonce(engine, challenge, threshold_val);

        // 3. 通过 transcript 发送 nonce
        prover_state.prover_message(::whir::transcript::U64(nonce));
    }

    /// 使用引擎查找函数进行证明（将 hash_id 解析为引擎）。
    template <typename Transcript, typename EngineLookup>
    void prove(Transcript& prover_state, EngineLookup&& lookup) const {
        if (threshold_val == UINT64_MAX) return;
        prove(prover_state, lookup(hash_id));
    }

    /// 零难度便捷重载（无需引擎）。
    template <typename Transcript>
    void prove(Transcript&) const {
        assert(threshold_val == UINT64_MAX && "Non-zero PoW requires a HashEngine");
    }

    // ---- verify: 挤压挑战，读取 nonce，验证 ----

    /// 使用显式引擎引用进行验证。
    template <typename Transcript>
    bool verify(Transcript& verifier_state,
                const ::whir::hash::HashEngine& engine) const
    {
        if (threshold_val == UINT64_MAX) return true;

        // 1. 挤压挑战（与证明者相同的确定性值）
        auto challenge = verifier_state.template verifier_message<std::array<std::uint8_t, 32>>();

        // 2. 从 transcript 读取 nonce
        ::whir::transcript::U64 nonce_u64;
        if (!verifier_state.prover_message(nonce_u64)) return false;

        // 3. 验证 nonce 满足阈值
        return check_nonce(engine, challenge, nonce_u64.value, threshold_val);
    }

    /// 使用引擎查找函数进行验证。
    template <typename Transcript, typename EngineLookup>
    bool verify(Transcript& verifier_state, EngineLookup&& lookup) const {
        if (threshold_val == UINT64_MAX) return true;
        return verify(verifier_state, lookup(hash_id));
    }

    /// 零难度便捷重载。
    template <typename Transcript>
    bool verify(Transcript&) const {
        assert(threshold_val == UINT64_MAX && "Non-zero PoW requires a HashEngine");
        return true;
    }
};

} // namespace whir::protocols::pow
