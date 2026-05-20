#pragma once

// ============================================================================
// engines.hpp — 可插拔密码原语的引擎注册系统
//
// WHIR 使用 EngineId 查找系统将协议参数与具体实现解耦。
// 协议层通过 32 字节标识符引用哈希函数 (SHA-256, BLAKE3),
// 而非具体类型, 从而支持运行时配置。
//
// 核心类型:
//   EngineId      — 32 字节标识符, SHA3-256(name) 截断
//   Engine        — 所有引擎类型的抽象基类
//   Engines<T>    — 线程安全注册表 (mutex + unordered_map)
//
// EngineId 生成规则:
//   SHA3-256(b"whir::hash" || b"sha2") → 前 32 字节 = ENGINE_ID_SHA2
//   保证 prover 和 verifier 无需运行时协商即使用同一哈希函数。
//
// 对应 Rust: src/engines.rs
// ============================================================================

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

// ============================================================================
// EngineId — 32 字节全局唯一引擎标识符
// ============================================================================
class EngineId {
public:
    constexpr EngineId() noexcept : bytes_{} {}
    constexpr explicit EngineId(const std::array<std::uint8_t, 32>& b) noexcept : bytes_(b) {}

    constexpr const std::array<std::uint8_t, 32>& bytes() const noexcept { return bytes_; }
    std::span<const std::uint8_t> as_slice() const noexcept {
        return std::span<const std::uint8_t>{bytes_.data(), bytes_.size()};
    }

    friend constexpr bool operator==(const EngineId& a, const EngineId& b) noexcept {
        return a.bytes_ == b.bytes_;
    }
    friend constexpr bool operator!=(const EngineId& a, const EngineId& b) noexcept {
        return !(a == b);
    }

    // 短格式 (默认): 前 6 字节 + "..." + 后 6 字节; 完整格式: 32 字节全量十六进制
    friend std::ostream& operator<<(std::ostream& os, const EngineId& id) {
        return id.print(os, /*full=*/false);
    }

    std::ostream& print(std::ostream& os, bool full) const {
        const auto save_flags = os.flags();
        os << std::hex << std::setfill('0');
        if (full) {
            for (auto b : bytes_)
                os << std::setw(2) << static_cast<unsigned>(b);
        } else {
            for (std::size_t i = 0; i < 6; ++i)
                os << std::setw(2) << static_cast<unsigned>(bytes_[i]);
            os.flags(save_flags);
            os << "...";
            os << std::hex << std::setfill('0');
            for (std::size_t i = 26; i < 32; ++i)
                os << std::setw(2) << static_cast<unsigned>(bytes_[i]);
        }
        os.flags(save_flags);
        return os;
    }

private:
    std::array<std::uint8_t, 32> bytes_;
};

// 哨兵值: 未选择任何引擎
constexpr EngineId ENGINE_ID_NONE{};

// ============================================================================
// Engine — 所有可插拔引擎的抽象基类
// ============================================================================
class Engine {
public:
    virtual ~Engine() = default;
    virtual EngineId engine_id() const = 0;
};

// ============================================================================
// Engines<T> — 线程安全引擎注册表
//
// 维护 EngineId → shared_ptr<T> 映射, 所有公开方法均受互斥锁保护。
// 用法:
//   Engines<HashEngine> registry;
//   registry.register_engine(std::make_shared<Sha2>());
//   auto e = registry.retrieve(ENGINE_ID_SHA2);  // 未注册时返回 nullptr
//
// 对应 Rust: ENGINES (LazyLock<Mutex<HashMap>>)
// ============================================================================

template <typename T>
class Engines {
public:
    Engines() = default;
    Engines(const Engines&) = delete;
    Engines& operator=(const Engines&) = delete;

    void register_engine(std::shared_ptr<T> engine) {
        assert(engine);
        const EngineId id = engine->engine_id();
        std::lock_guard<std::mutex> lock(mu_);
        map_[id] = std::move(engine);
    }

    bool contains(EngineId id) const {
        std::lock_guard<std::mutex> lock(mu_);
        return map_.find(id) != map_.end();
    }

    std::shared_ptr<T> retrieve(EngineId id) const {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = map_.find(id);
        if (it == map_.end()) return {};
        return it->second;
    }

private:
    // FNV-1a 风格哈希, 仅影响桶分配, 碰撞不影响正确性 (相等性比较全部 32 字节)
    struct EngineIdHash {
        std::size_t operator()(const EngineId& id) const noexcept {
            std::size_t h = 0;
            const auto& bytes = id.bytes();
            for (std::size_t i = 0; i < 32; ++i) {
                h = h * 1099511628211ULL ^ bytes[i];
            }
            return h;
        }
    };

    mutable std::mutex mu_;
    std::unordered_map<EngineId, std::shared_ptr<T>, EngineIdHash> map_;
};

} // namespace whir
