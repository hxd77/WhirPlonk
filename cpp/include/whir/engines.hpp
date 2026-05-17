#pragma once

// ===========================================================================
// engines.hpp
// 对应 WHIR 中的 src/engines.rs。
//
// WHIR 的「引擎注册系统」— 用 32 字节的 EngineId 来标识和查找具体的引擎实现。
//
// 核心组件:
//   1. EngineId        — 32 字节全局唯一标识符 (SHA3-256 哈希值)
//   2. Engine          — 所有引擎的抽象基类 (hash engine、NTT engine 等)
//   3. Engines<T>      — 线程安全的引擎注册表 (mutex + map)
//
// 为什么需要 EngineId?
//   WHIR 协议参数中需要指定使用哪种哈希函数 (SHA-256 / BLAKE3 等)。
//   EngineId 是约定好的常量 (通常用 SHA3-256(b"whir::hash" + name) 生成),
//   协议双方通过相同的 EngineId 保证使用相同的哈希算法。
//
// 对应 Rust:
//   EngineId    ← src/engines.rs 中的 EngineId
//   Engine      ← trait Engine
//   Engines<T>  ← struct Engines<T> (TypeMap pattern)
// ===========================================================================

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <mutex>
#include <ostream>
#include <span>
#include <unordered_map>

namespace whir {

// ===========================================================================
// EngineId — 32 字节引擎标识符
//
// 用 SHA3-256 对引擎名称哈希产生, 保证全局唯一且不冲突。
// 例如 SHA2 引擎的 ID 是 SHA3-256(b"whir::hash" + b"sha2") 的前 32 字节。
//
// 接口:
//   EngineId()               — 零填充 ID (ENGINE_ID_NONE)
//   EngineId(array<u8,32>)   — 从 32 字节构造
//   bytes()                  — 返回 32 字节数组 (只读)
//   as_slice()               — 返回 span<const u8> (用于作为哈希输入)
//   operator<<               — 打印为短格式 (前6字节...后6字节) 或完整格式
// ===========================================================================

class EngineId {
public:
    /// 默认构造 — 全零, 表示 "无引擎" (对应 Rust 的 NONE = EngineId([0u8; 32]))
    constexpr EngineId() noexcept : bytes_{} {}

    /// 从 32 字节数组显式构造
    constexpr explicit EngineId(const std::array<std::uint8_t, 32>& b) noexcept : bytes_(b) {}

    /// 只读访问原始 32 字节
    constexpr const std::array<std::uint8_t, 32>& bytes() const noexcept { return bytes_; }

    /// 以 span 形式访问 (用于传给哈希函数)
    std::span<const std::uint8_t> as_slice() const noexcept {
        return std::span<const std::uint8_t>{bytes_.data(), bytes_.size()};
    }

    // ---- 比较运算符 (三路比较 = default, 按字节序比较) ----
    friend constexpr bool operator==(const EngineId& a, const EngineId& b) noexcept {
        return a.bytes_ == b.bytes_;
    }
    friend constexpr bool operator!=(const EngineId& a, const EngineId& b) noexcept {
        return !(a == b);
    }

    // ---- 打印 ----
    // 短格式 (默认): 显示前 6 字节 + "..." + 后 6 字节
    //   例如 "018eaa247cb8...c8f2f76bb076"
    // 完整格式 (print(full=true)): 显示全部 64 位十六进制
    //
    // 与 Rust 端保持一致: {} 输出短格式, {:#} 输出完整格式
    friend std::ostream& operator<<(std::ostream& os, const EngineId& id) {
        return id.print(os, /*full=*/false); //false表示短格式打印
    }

    std::ostream& print(std::ostream& os, bool full) const {
        const auto save_flags = os.flags();
        os << std::hex << std::setfill('0'); //十六进制输出同时用"0"填充不用空格

        if (full) {
            // 完整格式: 32 字节全部打印, 每字节 2 位十六进制 → 共 64 字符
            for (auto b : bytes_)
                os << std::setw(2) << static_cast<unsigned>(b);
        } else {
            // 短格式: 前 6 字节 + "..." + 后 6 字节
            for (std::size_t i = 0; i < 6; ++i)
                os << std::setw(2) << static_cast<unsigned>(bytes_[i]);
            os.flags(save_flags);  // 恢复标志后再输出 "..."
            os << "...";
            os << std::hex << std::setfill('0');
            for (std::size_t i = 26; i < 32; ++i)
                os << std::setw(2) << static_cast<unsigned>(bytes_[i]);
        }

        os.flags(save_flags);
        return os;
    }

private:
    std::array<std::uint8_t, 32> bytes_;  // 32 字节标识数据一个字节8bit
};

// "无引擎" 常量 — 全零 EngineId
constexpr EngineId ENGINE_ID_NONE{};

// ===========================================================================
// Engine — 所有引擎实现的抽象基类
//
// WHIR 中的 "引擎" 是指可以通过 EngineId 注册和查找的服务:
//   - HashEngine (哈希引擎: SHA-256, BLAKE3, Copy, ...)
//   - NttEngine (NTT 引擎: 域相关的 FFT 变换)
//
// 每个引擎子类必须实现 engine_id() 返回自己的唯一标识。
//
// 使用方式:
//   engines.retrieve(hash_id)->hash_many(...)
//   或
//   直接用 concret engine (不需要通过注册表): goldilocks_engine().ntt(...)
// ===========================================================================

class Engine {
public:
    virtual ~Engine() = default;

    /// 返回此引擎的全局唯一标识符
    virtual EngineId engine_id() const = 0;
};

// ===========================================================================
// Engines<T> — 线程安全的引擎注册表
//
// 模板参数 T: 引擎接口类型 (Engine 的派生类), 如 HashEngine
//
// 用法:
//   Engines<HashEngine> hash_engines;
//   hash_engines.register_engine(std::make_shared<Sha2>());
//   auto engine = hash_engines.retrieve(ENGINE_ID_SHA2);
//
// 线程安全: 所有公开方法都用 mutex 保护。
//
// 对应 Rust: src/engines.rs 的 ENGINES (全局 LazyLock<Mutex<HashMap>>)
//   C++ 端不做全局单例 — 调用方按需创建 Engines 实例或直接用具体引擎。
// ===========================================================================

template <typename T>
class Engines {
public:
    Engines() = default;

    // 禁止拷贝 — 注册表应该只有一个所有者
    Engines(const Engines&) = delete;
    Engines& operator=(const Engines&) = delete;

    /// 注册一个引擎 (如果同 ID 已有则覆盖)
    void register_engine(std::shared_ptr<T> engine) { //shared_ptr表示一个计数器共享指针
        assert(engine); //不是空指针
        const EngineId id = engine->engine_id(); //返回唯一标识符
        std::lock_guard<std::mutex> lock(mu_);//把门锁死，开始修改数据
        map_[id] = std::move(engine);
        //因为engine是局部变量,move把所有权交给map_
    }

    /// 检查是否包含指定 ID 的引擎
    bool contains(EngineId id) const {
        std::lock_guard<std::mutex> lock(mu_);
        return map_.find(id) != map_.end(); //map_.end()表示找不到
    }

    /// 按 ID 查找引擎, 如果未注册则返回空指针
    /// 调用方需要检查返回值是否为空
    std::shared_ptr<T> retrieve(EngineId id) const {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = map_.find(id); //find方法返回一个迭代器
        if (it == map_.end()) return {};
        return it->second; //it->first表示键,it->second表示值
    }

private:
    // ---- EngineId 的哈希函数 ----
    // 用 FNV-1a 风格的滚动哈希聚合 32 字节。
    // 哈希值只用于 hash map 分桶, 碰撞不影响正确性 (equality 仍然比较全部 32 字节)。
    struct EngineIdHash {
        std::size_t operator()(const EngineId& id) const noexcept {
            std::size_t h = 0;
            const auto& bytes = id.bytes();
            for (std::size_t i = 0; i < 32; ++i) {
                // 乘数 1099511628211 = 0x100000001B3 (一个常用的 FNV 哈希乘数)
                h = h * 1099511628211ULL ^ bytes[i];
            }
            return h;
        }
    };

    mutable std::mutex mu_;                                    // 保护 map_ 的互斥锁

    //无序的哈希表EngineId是键,std::shared_ptr<T>是value,EngineIdHash把EngineId转换成数字哈希值这样undered_map才嫩把它存进底层的哈希表中  
    std::unordered_map<EngineId, std::shared_ptr<T>, EngineIdHash> map_;  // ID → 引擎实例
};

} // namespace whir
