#pragma once

// ===========================================================================
// proof_of_work.hpp — Proof of Work 工作量证明
// 对应 WHIR 中的 src/protocols/proof_of_work.rs。
//
// 在 WHIR 的 sumcheck 轮次中插入 PoW 来增加证明者计算成本,
// 从而补偿 round-by-round soundness 中的信息论差距。
//
// 协议:
//   输入布局 (64 字节):
//     [0..32):   challenge (32B)   — 从 transcript 挤出的随机字节
//     [32..40):  nonce (8B, LE)    — prover 找的小整数
//     [40..64):  zeros (24B)       — 零填充 (对齐 SHA-256/BLAKE3 块大小)
//
//   条件: hash(input) 的前 8 字节解释为 LE u64, 必须 ≤ threshold
//
// 难度编码:
//   threshold(difficulty_bits) = ceil(2^(64 - difficulty_bits))
//   difficulty=0  → threshold=UINT64_MAX (任何 nonce 都通过)
//   difficulty=60 → threshold=2^4=16    (极难通过)
//
// 组件:
//   纯函数层: threshold, difficulty_of, find_nonce, check_nonce
//   协议层:   PowConfig (带 transcript 交互的 prove/verify)
//
// 注意: 批处理优化 (preferred_batch_size) 可以并行检查多个 nonce,
//       但最终结果是全局最小 nonce (与顺序搜索等价)。
//
// 对应 Rust: src/protocols/proof_of_work.rs
// 对应 C++:  hash/hash_engine.hpp (HashEngine)
// ===========================================================================

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

// ===========================================================================
// 难度 ↔ 阈值换算
// ===========================================================================

//根据给定的难度值计算出一个64位无符号整数的目标阈值
/// 从难度位数计算阈值: threshold = ceil(2^(64 - difficulty))
/// difficulty=0 时返回 UINT64_MAX (2^64 超出 u64 范围)
inline std::uint64_t threshold(::whir::Bits difficulty) { //dificulty是一个表示难度的数值
    const double d = static_cast<double>(difficulty);
    assert(d >= 0.0 && d <= 60.0);  // >60 位几乎不可能找到 nonce
    const double t = std::ceil(std::exp2(64.0 - d)); //t=2^(64-difficulty)
    if (t >= static_cast<double>(UINT64_MAX)) return UINT64_MAX;
    return static_cast<std::uint64_t>(t);
}

//log2(threshold)=64-difficulty,所以difficulty=64-log2(threshold)
/// 从阈值反推难度位数: difficulty = 64 - log2(threshold)
inline ::whir::Bits difficulty_of(std::uint64_t threshold) {
    return ::whir::Bits{64.0 - std::log2(static_cast<double>(threshold))};
} 

// ===========================================================================
// 纯函数: 哈希工具
// ===========================================================================

///从一个较长的哈希值中提取前8个字节，并按小端序将它们拼接成一个64位无符号整数u64
inline std::uint64_t hash_to_u64_le(const ::whir::hash::Hash& h) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | static_cast<std::uint64_t>(h[i]);
    }
    return v;
}

// ===========================================================================
// 纯函数: nonce 查找 (no transcript)
// ===========================================================================

/// 单线程顺序搜索最小 nonce, 使得 hash(challenge || nonce_le || zeros) ≤ threshold。
/// 支持批处理 (batch = engine.preferred_batch_size()), 但结果等价于顺序搜索。
//在一个无限循环中,利用批量计算Batching尝试不同的nonce,直到找到一个nonce,使得生成的哈希值小于等于threshold
inline std::uint64_t find_nonce(
    const ::whir::hash::HashEngine& engine,
    const std::array<std::uint8_t, 32>& challenge,
    std::uint64_t threshold)
{
    // 零难度: 任何 nonce 都通过, 直接返回 0
    if (threshold == UINT64_MAX) return 0;

    //获取底层硬件推荐的批量大小(比如CPU可能是4或8,GPU可能更大)
    const std::size_t batch = engine.preferred_batch_size();

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

            std::vector<std::uint8_t> inputs(64 * batch, 0);
            std::vector<::whir::hash::Hash> outputs(batch);
            for (std::size_t i = 0; i < batch; ++i) {
                std::memcpy(&inputs[64 * i], challenge.data(), 32);
            }

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

    // 输入缓冲: batch 个 64B 块 (challenge + nonce + zeros)
    std::vector<std::uint8_t> inputs(64 * batch, 0);
    std::vector<::whir::hash::Hash> outputs(batch);

    // 预先将challenge(32字节)填入每一个batch的前半部分
    for (std::size_t i = 0; i < batch; ++i) {
        std::memcpy(&inputs[64 * i], challenge.data(), 32);
        //块 0: [32字节 Challenge] [8字节 Nonce] [24字节 全0]
        //块 1: [32字节 Challenge] [8字节 Nonce] [24字节 全0]
    }

    //base是当前批次的起始nonce值，每次循环增加一个batch的数量
    for (std::uint64_t base = 0;; base += static_cast<std::uint64_t>(batch)) {
        // 写入本批所有 nonce (LE)
        for (std::size_t i = 0; i < batch; ++i) {
            //计算当前块对应的具体nonce值
            const std::uint64_t n = base + static_cast<std::uint64_t>(i);
            for (int b = 0; b < 8; ++b) {
                //将64位的nonce拆成8个字节,按小端序填入input
                inputs[64 * i + 32 + b] = static_cast<std::uint8_t>((n >> (8 * b)) & 0xFFu);
            }
        }

        //计算出batch个哈希值,每个大小为64字节
        engine.hash_many(64,
            std::span<const std::uint8_t>{inputs.data(), inputs.size()},
            std::span<::whir::hash::Hash>{outputs.data(), outputs.size()});

        // 检查本批结果, 返回第一个满足条件的 nonce
        for (std::size_t i = 0; i < batch; ++i) {
            //调用hash_to_u64_le,把哈希的前8字节变成数字
            //和threshold比大小
            if (hash_to_u64_le(outputs[i]) <= threshold) {
                //如果小于阈值,说明成功返回nonce
                return base + static_cast<std::uint64_t>(i);
            }
        }
    }//如果没有进入下一轮,base增加
}

// 验证单个 nonce 是否满足 PoW 条件\]
//接受nonce,按照同样规则计算一次hash,观察结果是否满足条件
inline bool check_nonce(
    const ::whir::hash::HashEngine& engine,
    const std::array<std::uint8_t, 32>& challenge,
    std::uint64_t nonce,
    std::uint64_t threshold)
{
    if (threshold == UINT64_MAX) return true;  // 零难度必定通过(难度最低,阈值为最大)

    // 构造完整输入
    std::array<std::uint8_t, 64> input{};
    std::memcpy(input.data(), challenge.data(), 32);   // 前32字节challenge (32B)
    for (int b = 0; b < 8; ++b) {
        //小端序填入nonce [32-39]字节
        input[32 + b] = static_cast<std::uint8_t>((nonce >> (8 * b)) & 0xFFu);  // nonce LE
    }
    // [40..64) 已经是零 (默认填充)

    ::whir::hash::Hash out{};
    //执行哈希计算
    engine.hash_many(64,
        std::span<const std::uint8_t>{input.data(), input.size()},
        std::span<::whir::hash::Hash>{&out, 1});
    return hash_to_u64_le(out) <= threshold; //判断是否满足条件
}

// ===========================================================================
// PowConfig — 协议层: 带 transcript 交互的 PoW 配置
// 对应 Rust proof_of_work::Config
// ===========================================================================

struct PowConfig {
    ::whir::EngineId hash_id;              // 使用的哈希引擎 ID
    std::uint64_t threshold_val = UINT64_MAX;  // 阈值 (UINT64_MAX = 零难度)

    ::whir::Bits difficulty() const { return difficulty_of(threshold_val); } //难度位数

    // ---- prove: 获取 challenge, 找 nonce, 发送 nonce ----

    /// 带 engine 引用的 prove
    template <typename Transcript>
    void prove(Transcript& prover_state,
               const ::whir::hash::HashEngine& engine) const
    {
        if (threshold_val == UINT64_MAX) return;  // 零难度 — 跳过

        //1.获取challenge:从transcript中挤出32字节的随机数作为挑战
        auto challenge = prover_state.template verifier_message<std::array<std::uint8_t, 32>>();
        
        //2.调用find_nonce找nonce
        std::uint64_t nonce = find_nonce(engine, challenge, threshold_val);

        //3.把Nonce写回transcipt中
        prover_state.prover_message(::whir::transcript::U64(nonce));
    }

    /// 带 engine lookup 函数的 prove (通过 hash_id 查找 engine)
    //不需要传哈希引擎,而是传一个"查找函数",代码会根据hash_id找到对应的引擎
    template <typename Transcript, typename EngineLookup>
    void prove(Transcript& prover_state, EngineLookup&& lookup) const {
        if (threshold_val == UINT64_MAX) return;
        prove(prover_state, lookup(hash_id));
    }

    /// 单参数便捷版: 仅零难度可用,如果不传hash引擎,难度直接为0通过
    template <typename Transcript>
    void prove(Transcript&) const {
        assert(threshold_val == UINT64_MAX && "非零 PoW 需要提供 HashEngine");
    }

    // ---- verify: 挤出 challenge, 读取 nonce, 验证 ----

    /// 带 engine 引用的 verify
    template <typename Transcript>
    bool verify(Transcript& verifier_state,
                const ::whir::hash::HashEngine& engine) const
    {
        if (threshold_val == UINT64_MAX) return true; //零难度直接对

        //1.从transcript中生成32字节的挑战
        auto challenge = verifier_state.template verifier_message<std::array<std::uint8_t, 32>>();
        ::whir::transcript::U64 nonce_u64;

        //2.从transcript中读取nonce
        if (!verifier_state.prover_message(nonce_u64)) return false;

        //3.调用check_nonce验证nonce
        return check_nonce(engine, challenge, nonce_u64.value, threshold_val);
    }

    /// 带 engine lookup 函数的 verify
    template <typename Transcript, typename EngineLookup>
    bool verify(Transcript& verifier_state, EngineLookup&& lookup) const {
        if (threshold_val == UINT64_MAX) return true;
        return verify(verifier_state, lookup(hash_id));
    }

    /// 单参数便捷版: 仅零难度可用
    template <typename Transcript>
    bool verify(Transcript&) const {
        assert(threshold_val == UINT64_MAX && "非零 PoW 需要提供 HashEngine");
        return true;
    }
};

} // namespace whir::protocols::pow
