#pragma once

// ===========================================================================
// hash_counter.hpp — 哈希调用计数器的全局单例
// 对应 WHIR 中的 src/hash/hash_counter.rs。
//
// 每次 hash_many() 调用后累加消息数量，用于性能测量和基准测试。
// 用 std::atomic 保证多线程安全（即使 C++ 端目前主要是单线程）。
//
// 用法:
//   hash_counter().add(output_count);   // 引擎内部调用
//   auto n = hash_counter().get();       // 基准测试中读取
//   hash_counter().reset();              // 测试前清零
//
// Rust 端对应: pub static HASH_COUNTER: LazyLock<AtomicUsize>
// ===========================================================================

#include <atomic>
#include <cstddef>

namespace whir::hash {

class HashCounter {
public:
    constexpr HashCounter() noexcept : value_(0) {}

    // 累加 count 个哈希操作。用 relaxed 序即可，不需要同步其他内存操作。
    void add(std::size_t count) noexcept { //count: 给计数器增加的数值
        value_.fetch_add(count, std::memory_order_relaxed); //fetch_add表示原子相加,memory_order_relaxed表示宽松内存序，更快
        //Relaxed 的含义： relaxed（宽松的）是在告诉编译器和 CPU：“别管那么宽！
        //我只要求 value_ 这个变量本身的加法是原子的（不漏加）就行了，不需要为了它去同步别的内存数据，也不用阻止指令重排。
    
    }

    // 清零 (测试开始时调用)。用 seq_cst 保证之前的写入对后续读可见。
    void reset() noexcept {
        value_.store(0, std::memory_order_seq_cst); //store表示写入0,memory_order_seq_cst表示顺序一致性
        //它会强制刷新所有 CPU 核心的高速缓存。一旦这个线程执行了重置为 0 的操作，
        //系统中的所有其他线程，在下一微秒读取到的绝对是 0，绝不允许任何线程因为缓存没更新而读到旧的脏数据。

    }

    // 读取当前计数。用 seq_cst 保证看到最新值。
    std::size_t get() const noexcept {
        return value_.load(std::memory_order_seq_cst); //load表示加载读取
    }

private:
    std::atomic<std::size_t> value_; //一个线程安全的无符号整数变量
};

/// 全局单例 — 函数内 static 保证线程安全的延迟初始化 (C++11 起)
inline HashCounter& hash_counter() {
    static HashCounter c;
    return c;
}

} // namespace whir::hash
