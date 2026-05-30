#pragma once

// ============================================================================
// hash_counter.hpp — 全局原子哈希计数器
//
// 单例计数器，累加通过 hash_many() 处理的消息总数。
// 用于性能度量与基准测试。
//
// 线程安全：基于 std::atomic，递增使用 relaxed 语义（仅需原子性），
// 重置/读取使用 seq_cst（保证跨线程可见性）。
//
// 用法:
//   hash_counter().add(output_count);   // 引擎实现内部调用
//   auto n = hash_counter().get();       // 基准测试中读取
//   hash_counter().reset();              // 测试前清零
//
// 对应 Rust 文件: src/hash/hash_counter.rs
//   Rust: pub static HASH_COUNTER: LazyLock<AtomicUsize>
// ============================================================================

#include <atomic>
#include <cstddef>

namespace whir::hash {

class HashCounter {
public:
    constexpr HashCounter() noexcept : value_(0) {}

    // 累加 `count` 条已哈希消息。relaxed 语义足够——仅需保证本变量的原子性，
    // 无需跨变量同步。
    void add(std::size_t count) noexcept {
        value_.fetch_add(count, std::memory_order_relaxed);
    }

    // 将计数器重置为零。使用 seq_cst 确保所有线程在后续 load 前可见此写入，
    // 这对测试隔离至关重要。
    void reset() noexcept {
        value_.store(0, std::memory_order_seq_cst);
    }

    // 读取当前计数值。使用 seq_cst 保证返回最新值。
    std::size_t get() const noexcept {
        return value_.load(std::memory_order_seq_cst);
    }

private:
    std::atomic<std::size_t> value_;
};

// Meyers 单例——C++11 起保证线程安全的惰性初始化。
inline HashCounter& hash_counter() {
    static HashCounter c;
    return c;
}

} // namespace whir::hash
