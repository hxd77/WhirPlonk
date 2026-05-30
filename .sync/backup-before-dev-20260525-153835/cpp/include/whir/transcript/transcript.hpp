#pragma once

// ===========================================================================
// transcript.hpp — Fiat-Shamir 转录层 (SHAKE-128 XOF 双工海绵)
//
// 基于 SHAKE-128 双工海绵实现 WHIR 转录协议, 与 Rust spongefish::StdHash
// 字节级兼容。
//
// 海绵操作:
//   absorb  → shake128_absorb
//   squeeze → shake128_xof_clone + shake128_xof_read (重建 XOF 读取器)
//   ratchet → 空操作 (WHIR 协议未使用, 对应 Rust todo!())
//
// 核心类型:
//   DuplexSponge            — 双工海绵抽象接口
//   Shake128DuplexSponge    — SHAKE-128 实现 (spongefish::StdHash)
//   DomainSeparator         — 协议/会话/实例三元组 (域分离)
//   ProverState             — Fiat-Shamir 证明者状态 (证明生成)
//   VerifierState           — Fiat-Shamir 验证者状态 (确定性重放)
//   Empty / U64             — 编解码辅助类型 (对标 Rust codecs.rs)
//   CBOR 辅助函数           — DomainSeparator 的最小 CBOR 编码
//   Narg 序列化             — 证明线格式 (narg_string + hints)
//
// DomainSeparator:
//   protocol_id = SHA3-512(CBOR(config))   — 64 B
//   session_id  = SHA3-256(CBOR(session))  — 32 B
// ===========================================================================

#include "../algebra/goldilocks.hpp"
#include "../algebra/goldilocks_ext2.hpp"
#include "../algebra/goldilocks_ext3.hpp"
#include "../hash/hash_engine.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

extern "C" {
#include "keccak.h"
}

namespace whir::transcript {

// ===========================================================================
// DuplexSponge — 双工海绵抽象接口
// ===========================================================================

class DuplexSponge {
public:
    virtual ~DuplexSponge() = default;
    virtual void absorb(std::span<const std::uint8_t> input) = 0;
    virtual void squeeze(std::span<std::uint8_t> output) = 0;
    virtual void ratchet() = 0;
    virtual std::unique_ptr<DuplexSponge> clone() const = 0;
};

// ===========================================================================
// Shake128DuplexSponge — SHAKE-128 XOF 双工海绵
//
// 对应 Rust spongefish::XOF<sha3::Shake128> (StdHash)。
//
// 关键语义: 每次 squeeze 调用克隆 hasher、终结 XOF 并从读取器读取。
// 因此 squeeze(1); squeeze(1) != squeeze(2) — XOF 读取器每次重建, 与
// Rust 行为一致。
//
// absorb:  使 xof_reader 失效, 然后向 hasher 输入数据
// squeeze: 惰性克隆+终结 hasher 为 xof_reader, 然后读取
// ratchet: 空操作 (WHIR 协议从不调用)
// ===========================================================================

// SHAKE-128 双工海绵状态机
class Shake128DuplexSponge final : public DuplexSponge {
public:
    Shake128DuplexSponge() { shake128_init(&hasher_); }

    void absorb(std::span<const std::uint8_t> input) override {
        // 使 xof_reader 失效, 然后向 hasher 输入数据
        has_xof_ = false;
        if (!input.empty())
            shake128_absorb(&hasher_, input.data(), input.size());
    }

    void squeeze(std::span<std::uint8_t> output) override {
        if (output.empty()) return;
        // 首次 squeeze 时克隆 hasher → finalize_xof; 后续 squeeze 复用读取器
        if (!has_xof_) {
            xof_reader_ = shake128_xof_clone(&hasher_);
            has_xof_ = true;
        }
        shake128_xof_read(&xof_reader_, output.data(), output.size());
    }

    void ratchet() override {
        // Rust XOF ratchet 为 todo!(); WHIR 协议从不调用此方法
    }

    std::unique_ptr<DuplexSponge> clone() const override {
        auto c = std::make_unique<Shake128DuplexSponge>();
        c->hasher_ = hasher_;
        c->has_xof_ = has_xof_;
        c->xof_reader_ = xof_reader_;
        return c;
    }

    // 一次性 SHAKE-128 哈希: 吸收输入 → 克隆+终结 XOF → 读取输出
    static void shake128_hash(const std::uint8_t* data, std::size_t len,
                               std::span<std::uint8_t> out) {
        shake128_ctx ctx;
        shake128_init(&ctx);
        shake128_absorb(&ctx, data, len);
        shake128_ctx xof = shake128_xof_clone(&ctx);
        shake128_xof_read(&xof, out.data(), out.size());
    }

    // SHA3-256 摘要: 32 字节输出
    static void sha3_256_digest(const std::uint8_t* data, std::size_t len,
                                 std::array<std::uint8_t, 32>& out) {
        sha3_256_hash(data, len, out.data());
    }

    // SHA3-512 摘要: 64 字节输出
    static void sha3_512_digest(const std::uint8_t* data, std::size_t len,
                                 std::array<std::uint8_t, 64>& out) {
        sha3_512_hash(data, len, out.data());
    }

private:
    shake128_ctx hasher_;       // SHAKE-128 吸收状态
    shake128_ctx xof_reader_;   // XOF 挤压读取器 (克隆+终结)
    bool has_xof_ = false;      // xof_reader_ 是否有效
};

// ===========================================================================
// 最小 CBOR 编码 — 用于 DomainSeparator, 匹配 Rust ciborium 输出
//
// CBOR (RFC 7049): 1 字节头部 (主类型 + 附加信息) + 可选长度 + 载荷。
// 所有整数和长度采用大端序 (RFC 7049 Section 2.1)。
//
// Rust ciborium + serde 将结构体序列化为 CBOR **映射** (主类型 5, 字段名
// 作为文本键), 而非数组。为逐字节匹配 Rust 输出, 每个 C++ 结构体需要
// 手写 cbor_encode 特化。本文件提供 uint/string/array/vector 的基础编码器。
// ===========================================================================

// CBOR 无符号整数 (主类型 0)。v > 23 时需要额外长度字节。
inline void cbor_write_uint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    if (v <= 23) {
        out.push_back(static_cast<std::uint8_t>(v));
    } else if (v <= 0xFF) {
        out.push_back(0x18); out.push_back(static_cast<std::uint8_t>(v));
    } else if (v <= 0xFFFF) {
        out.push_back(0x19);
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));   // 高字节在前
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    } else if (v <= 0xFFFFFFFF) {
        out.push_back(0x1A);
        out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    } else {
        out.push_back(0x1B);
        out.push_back(static_cast<std::uint8_t>((v >> 56) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 48) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 40) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 32) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }
}

// CBOR 文本字符串 (主类型 3)
inline void cbor_write_text(std::vector<std::uint8_t>& out,
                             std::string_view text) {
    std::uint64_t len = text.size();
    if (len <= 23) {
        out.push_back(static_cast<std::uint8_t>(0x60 + len));
    } else if (len <= 0xFF) {
        out.push_back(0x78); out.push_back(static_cast<std::uint8_t>(len));
    } else if (len <= 0xFFFF) {
        out.push_back(0x79);
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(len & 0xFF));
    } else {
        out.push_back(0x7A);
        out.push_back(static_cast<std::uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(len & 0xFF));
    }
    for (std::size_t i = 0; i < len; ++i)
        out.push_back(static_cast<std::uint8_t>(text[i]));
}

// CBOR 数组头部 (n 个元素, 大端长度编码)
inline void cbor_array_header(std::vector<std::uint8_t>& out, std::size_t n) {
    if (n <= 23) {
        out.push_back(static_cast<std::uint8_t>(0x80 + n));
    } else if (n <= 0xFF) {
        out.push_back(0x98); out.push_back(static_cast<std::uint8_t>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(0x99);
        out.push_back(static_cast<std::uint8_t>((n >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    } else {
        out.push_back(0x9A);
        out.push_back(static_cast<std::uint8_t>((n >> 24) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((n >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((n >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    }
}

// 结构体 → CBOR 数组 (需按类型特化)
template <typename T>
void cbor_encode(const T& value, std::vector<std::uint8_t>& out);

// string_view → CBOR 文本 (主类型 3)
inline void cbor_encode(std::string_view text, std::vector<std::uint8_t>& out) {
    cbor_write_text(out, text);
}

// 整数 → CBOR 无符号整数 (主类型 0)
inline void cbor_encode(std::uint32_t v, std::vector<std::uint8_t>& out) {
    cbor_write_uint(out, v);
}
inline void cbor_encode(std::uint64_t v, std::vector<std::uint8_t>& out) {
    cbor_write_uint(out, v);
}

// array → CBOR 数组
template <typename T, std::size_t N>
void cbor_encode(const std::array<T, N>& arr, std::vector<std::uint8_t>& out) {
    cbor_array_header(out, N);
    for (const auto& e : arr) cbor_encode(e, out);
}

// vector → CBOR 数组
template <typename T>
void cbor_encode(const std::vector<T>& vec, std::vector<std::uint8_t>& out) {
    cbor_array_header(out, vec.size());
    for (const auto& e : vec) cbor_encode(e, out);
}

// ===========================================================================
// Narg 序列化 — 证明线格式 (narg_string + hints)
//
// 每次 ProverState::prover_message 调用同时吸收海绵并追加到 narg_string。
// 验证者按相同顺序反序列化, 吸收海绵以确定性重放挑战。
//
// 平凡可复制类型: 原始 LE 字节拷贝 (匹配 Rust zerocopy)。
// vector<T>: 8 字节 LE 长度前缀 (u64, 匹配 arkworks CanonicalSerialize)。
// ===========================================================================
template <typename T>
void narg_serialize(const T& value, std::vector<std::uint8_t>& dst) {
    static_assert(std::is_trivially_copyable_v<T>,
        "需要为复杂类型特化 narg_serialize");
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    dst.insert(dst.end(), p, p + sizeof(T));
}

// 从字节跨度反序列化平凡可复制类型 T
template <typename T>
bool narg_deserialize(T& value, std::span<const std::uint8_t>& src) {
    static_assert(std::is_trivially_copyable_v<T>,
        "需要为复杂类型特化 narg_deserialize");
    if (src.size() < sizeof(T)) return false;
    std::memcpy(&value, src.data(), sizeof(T));
    src = src.subspan(sizeof(T));
    return true;
}

// vector<uint8_t> 特化: 8 字节 LE 长度前缀 (对标 arkworks CanonicalSerialize)
template <>
inline void narg_serialize<std::vector<std::uint8_t>>(
    const std::vector<std::uint8_t>& v, std::vector<std::uint8_t>& dst) {
    std::uint64_t len = static_cast<std::uint64_t>(v.size());
    narg_serialize(len, dst);
    dst.insert(dst.end(), v.begin(), v.end());
}

template <>
inline bool narg_deserialize<std::vector<std::uint8_t>>(
    std::vector<std::uint8_t>& v, std::span<const std::uint8_t>& src) {
    std::uint64_t len;
    if (!narg_deserialize(len, src)) return false;
    if (src.size() < len) return false;
    v.assign(src.data(), src.data() + static_cast<std::size_t>(len));
    src = src.subspan(static_cast<std::size_t>(len));
    return true;
}

// 通用 vector<T>: 8 字节 LE 长度前缀 (对标 arkworks)
template <typename T>
void narg_serialize(const std::vector<T>& v, std::vector<std::uint8_t>& dst) {
    static_assert(std::is_trivially_copyable_v<T>);
    std::uint64_t len = static_cast<std::uint64_t>(v.size());
    narg_serialize(len, dst);
    std::size_t bytes = v.size() * sizeof(T);
    const auto* p = reinterpret_cast<const std::uint8_t*>(v.data());
    dst.insert(dst.end(), p, p + bytes);
}

template <typename T>
bool narg_deserialize(std::vector<T>& v, std::span<const std::uint8_t>& src) {
    static_assert(std::is_trivially_copyable_v<T>);
    std::uint64_t len;
    if (!narg_deserialize(len, src)) return false;
    std::size_t bytes = static_cast<std::size_t>(len) * sizeof(T);
    if (src.size() < bytes) return false;
    v.resize(static_cast<std::size_t>(len));
    std::memcpy(v.data(), src.data(), bytes);
    src = src.subspan(bytes);
    return true;
}

// ===========================================================================
// 编码 — 值 → 字节 (用于海绵吸收)
//
// encode_to_bytes: 仅用于海绵吸收 (无长度前缀, 不写入证明)。
// narg_serialize:  用于证明线格式 (带长度前缀的向量)。
//
// 两者对平凡可复制类型均使用 LE 字节布局。
// 向量差异: encode_to_bytes 省略长度; narg_serialize 使用 8 字节 LE u64。
// ===========================================================================
template <typename T>
void encode_to_bytes(const T& value, std::vector<std::uint8_t>& out) {
    static_assert(std::is_trivially_copyable_v<T>);
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

template <typename T, std::size_t N>
void encode_to_bytes(const std::array<T, N>& arr, std::vector<std::uint8_t>& out) {
    for (const auto& e : arr) encode_to_bytes(e, out);
}

template <typename T>
void encode_to_bytes(const std::vector<T>& vec, std::vector<std::uint8_t>& out) {
    for (const auto& e : vec) encode_to_bytes(e, out);
}

inline void encode_to_bytes(std::span<const std::uint8_t> data,
                            std::vector<std::uint8_t>& out) {
    out.insert(out.end(), data.begin(), data.end());
}

inline void encode_to_bytes(const ::whir::hash::Hash& h,
                            std::vector<std::uint8_t>& out) {
    out.insert(out.end(), h.begin(), h.end());
}

// ===========================================================================
// 解码 — 海绵挤压字节 → 类型化值
//
// 对应 Rust spongefish::Decoding<[u8]>:
//   - 域元素 (Goldilocks 等): 挤压 (8+32)*ext_degree 字节, 然后
//     from_le_bytes_mod_order() 进行均匀规约。
//   - 小类型 (u64, Hash): 直接 LE 解码 sizeof(T) 字节。
// ===========================================================================

// 解码缓冲区大小 — 对标 Rust decoding_field_buffer_size()
// Goldilocks:     (8 + 32) * 1 = 40 B
// GoldilocksExt2: (8 + 32) * 2 = 80 B
// GoldilocksExt3: (8 + 32) * 3 = 120 B
template <typename T>
constexpr std::size_t decoding_buffer_size() {
    if constexpr (std::is_same_v<T, ::whir::algebra::Goldilocks>) return 40;
    else if constexpr (std::is_same_v<T, ::whir::algebra::GoldilocksExt2>) return 80;
    else if constexpr (std::is_same_v<T, ::whir::algebra::GoldilocksExt3>) return 120;
    else return sizeof(T);
}

// Goldilocks 稀疏模约: x mod p (p = 2^64 - 2^32 + 1)
// 前提: x < p * 2^8, 表示为 hi:lo，其中 hi < 256。
inline std::uint64_t reduce_mod_goldilocks_72(std::uint64_t hi, std::uint64_t lo) {
    constexpr std::uint64_t p = 0xFFFFFFFF00000001ULL;
    constexpr std::uint64_t epsilon = 0xFFFFFFFFULL;
    std::uint64_t term = hi * epsilon;
    std::uint64_t sum = lo + term;
    if (sum < lo) {
        const std::uint64_t old = sum;
        sum += epsilon;
        if (sum < old) sum += epsilon;
    }
    while (sum >= p) sum -= p;
    return sum;
}

// from_le_bytes_mod_order: 对标 arkworks from_le_bytes_mod_order
// 将所有字节视为 LE 大整数, 规约到 [0, p), 不转 Montgomery 域
inline std::uint64_t from_le_bytes_mod_order(const std::uint8_t* data, std::size_t len) {
    std::uint64_t acc = 0;
    for (std::size_t i = len; i > 0; --i) {
        const std::uint64_t hi = acc >> 56;
        const std::uint64_t lo = (acc << 8) | data[i - 1];
        acc = reduce_mod_goldilocks_72(hi, lo);
    }
    return acc;
}

// 从字节跨度解码 sizeof(T) 个 LE 字节到值
template <typename T>
T decode_from_bytes(std::span<const std::uint8_t> data) {
    static_assert(std::is_trivially_copyable_v<T>);
    assert(data.size() >= sizeof(T));
    T v;
    std::memcpy(&v, data.data(), sizeof(T));
    return v;
}

// Goldilocks 特化: 40 LE 字节 → from_le_bytes_mod_order → Goldilocks::from_u64
// 对标 Rust spongefish Decoding<[u8]>: Repr = DecodingFieldBuffer (40 B)
template <>
inline ::whir::algebra::Goldilocks decode_from_bytes<::whir::algebra::Goldilocks>(
    std::span<const std::uint8_t> data)
{
    assert(data.size() >= 40);
    std::uint64_t v = from_le_bytes_mod_order(data.data(), 40);
    return ::whir::algebra::Goldilocks::from_u64(v);
}

// GoldilocksExt2 特化: 80 LE 字节 → 两个 Goldilocks 分量
template <>
inline ::whir::algebra::GoldilocksExt2 decode_from_bytes<::whir::algebra::GoldilocksExt2>(
    std::span<const std::uint8_t> data)
{
    assert(data.size() >= 80);
    auto c0 = decode_from_bytes<::whir::algebra::Goldilocks>(data.subspan(0, 40));
    auto c1 = decode_from_bytes<::whir::algebra::Goldilocks>(data.subspan(40, 40));
    return ::whir::algebra::GoldilocksExt2{c0, c1};
}

// GoldilocksExt3 特化: 120 LE 字节 → 三个 Goldilocks 分量
template <>
inline ::whir::algebra::GoldilocksExt3 decode_from_bytes<::whir::algebra::GoldilocksExt3>(
    std::span<const std::uint8_t> data)
{
    assert(data.size() >= 120);
    auto c0 = decode_from_bytes<::whir::algebra::Goldilocks>(data.subspan(0, 40));
    auto c1 = decode_from_bytes<::whir::algebra::Goldilocks>(data.subspan(40, 40));
    auto c2 = decode_from_bytes<::whir::algebra::Goldilocks>(data.subspan(80, 40));
    return ::whir::algebra::GoldilocksExt3{c0, c1, c2};
}

// ===========================================================================
// 编解码辅助类型 — 对标 Rust src/transcript/codecs.rs
//
// spongefish 对 u64 没有 NargDeserialize (仅有 u32), 因此 WHIR 在 C++ 和
// Rust 两侧均定义了 U64 包装器。Empty 对应 Rust 的 ()。
// ===========================================================================

// Empty — 零字节编码, 用于不需要实例的协议
struct Empty {};
inline void encode_to_bytes(const Empty&, std::vector<std::uint8_t>&) {}
inline void cbor_encode(const Empty&, std::vector<std::uint8_t>& out) {
    out.push_back(0x80);  // CBOR 空数组, 匹配 Rust serde 对空结构体的序列化
}

// U64 — 8 字节 LE u64 包装器 (对标 spongefish::codecs::U64)
struct U64 {
    std::uint64_t value = 0;
    U64() = default;
    explicit U64(std::uint64_t v) : value(v) {}
};

// U64 海绵编码: 8 字节 LE (匹配 Rust impl Encoding<[u8]> for U64)
inline void encode_to_bytes(const U64& v, std::vector<std::uint8_t>& out) {
    for (int b = 0; b < 8; ++b)
        out.push_back(static_cast<std::uint8_t>((v.value >> (8 * b)) & 0xFFu));
}

// U64 挑战解码: 8 LE 字节 → u64
template <>
inline U64 decode_from_bytes<U64>(std::span<const std::uint8_t> data) {
    std::uint64_t v = 0;
    for (int b = 0; b < 8; ++b)
        v |= static_cast<std::uint64_t>(data[b]) << (8 * b);
    return U64(v);
}

// ===========================================================================
// DomainSeparator — 协议/会话/实例三元组 (域分离)
//
// Fiat-Shamir 安全性要求每个协议、会话和实例具有独立的转录状态。
// 吸收顺序必须与 Rust 完全一致:
//   1. sponge.absorb(protocol_id)              — 64 B
//   2. sponge.absorb(session_id)               — 32 B
//   3. sponge.absorb(encode_to_bytes(instance)) — 可变长度
//
// 用法 (链式调用):
//   auto ds = DomainSeparator::protocol(config)
//               .session("test_at_line_42")
//               .absorb_into(sponge, instance);
// ===========================================================================

struct DomainSeparator {
    std::array<std::uint8_t, 64> protocol_id{};
    std::array<std::uint8_t, 32> session_id{};

    // 从 C++ 配置对象派生 protocol_id (cbor_encode → SHA3-512)
    template <typename C>
    static DomainSeparator protocol(const C& config) {
        DomainSeparator ds;
        std::vector<std::uint8_t> cbor_buf;
        cbor_encode(config, cbor_buf);
        sha3_512_hash(cbor_buf.data(), cbor_buf.size(), ds.protocol_id.data());
        return ds;
    }

    // 追加会话标识符 (可链式调用: .protocol(config).session("name"))
    DomainSeparator session(std::string_view s) const {
        DomainSeparator ds = *this;
        std::vector<std::uint8_t> cbor_buf;
        cbor_encode(s, cbor_buf);                     // CBOR 文本编码
        sha3_256_hash(cbor_buf.data(), cbor_buf.size(), ds.session_id.data());
        return ds;
    }

    // 将所有域分离字段吸收进海绵
    // 注意: instance 使用 encode_to_bytes (原始字节), 非 CBOR —
    // 匹配 Rust spongefish 的 Encoding<[u8]> 实例吸收方式
    template <typename I>
    void absorb_into(DuplexSponge& sponge, const I& instance) const {
        sponge.absorb(protocol_id);
        sponge.absorb(session_id);
        std::vector<std::uint8_t> buf;
        encode_to_bytes(instance, buf);
        sponge.absorb(buf);
    }
};

// DomainSeparator 的 CBOR 编码 (空结构体 → 空 CBOR 数组)
inline void cbor_encode(const DomainSeparator&, std::vector<std::uint8_t>& out) {
    out.push_back(0x80);
}

// 后备: 未特化的平凡可复制类型 → CBOR 字节串 (主类型 2)
template <typename T>
void cbor_encode(const T& value, std::vector<std::uint8_t>& out) {
    static_assert(std::is_trivially_copyable_v<T>,
        "需要为此类型提供 cbor_encode 特化 (CBOR array 格式)");
    std::size_t len = sizeof(T);
    if (len <= 23) {
        out.push_back(static_cast<std::uint8_t>(0x40 + len));
    } else if (len <= 0xFF) {
        out.push_back(0x58); out.push_back(static_cast<std::uint8_t>(len));
    } else {
        out.push_back(0x59);
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(len & 0xFF));
    }
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

// 结构体需手动定义 cbor_encode 特化来覆盖上述后备:
//   inline void cbor_encode(const MyConfig& v, std::vector<std::uint8_t>& out) {
//       cbor_array_header(out, 2);
//       cbor_encode(v.a, out);
//       cbor_encode(v.b, out);
//   }

// ===========================================================================
// ProverState — Fiat-Shamir 证明者状态
//
// 三条并行流:
//   1. sponge_       — 双工海绵 (哈希链, 决定挑战)
//   2. narg_string_  — 证明字节流 (prover_message 追加至此)
//   3. hints_        — 带外提示 (如 Merkle 路径, 不被吸收)
//
// prover_message(msg) 三步 (顺序固定):
//   a) encode_to_bytes → 字节
//   b) sponge_->absorb  → 推进 Fiat-Shamir 状态
//   c) narg_serialize   → 追加到证明 (验证者按相同顺序读取)
//
// prover_hint(hint): 仅序列化, 不吸收海绵 (用于 Merkle 路径等大数据)
//
// verifier_message<T>(): 挤压 → 确定性挑战 (prover 与 verifier 海绵状态
//   同步, 因此挤压结果一致)
//
// 证明提取 (仅移动):
//   auto proof = std::move(ps).proof();
// ===========================================================================

class ProverState {
public:
    struct Proof {
        std::vector<std::uint8_t> narg_string;  // 序列化的 prover 消息
        std::vector<std::uint8_t> hints;         // 带外提示
    };

    ProverState() : sponge_(std::make_unique<Shake128DuplexSponge>()) {}

    // 从 DomainSeparator 构造: 吸收 protocol_id || session_id || encode(instance)
    template <typename I>
    static ProverState from_ds(const DomainSeparator& ds, const I& instance) {
        ProverState ps;
        ds.absorb_into(*ps.sponge_, instance);
        return ps;
    }

    // 发送证明者消息: encode → 吸收海绵 → 追加到证明
    template <typename T>
    void prover_message(const T& message) {
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(message, encoded);
        sponge_->absorb(encoded);
        narg_serialize(message, narg_string_);
    }

    // 带外提示: 仅序列化, 不吸收 (如 Merkle 路径)
    template <typename T>
    void prover_hint(const T& hint) {
        narg_serialize(hint, hints_);
    }

    // 吸收公开消息: 仅海绵, 不写入证明
    template <typename T>
    void public_message(const T& message) {
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(message, encoded);
        sponge_->absorb(encoded);
    }

    // 挤出验证者挑战: sponge.squeeze(decoding_buffer_size<T>()) → 解码 → T
    template <typename T>
    T verifier_message() {
        constexpr std::size_t buf_sz = decoding_buffer_size<T>();
        std::array<std::uint8_t, buf_sz> buf{};
        sponge_->squeeze(buf);
        return decode_from_bytes<T>(std::span<const std::uint8_t>{buf});
    }

    // 批量挤出 count 个挑战
    template <typename T>
    std::vector<T> verifier_message_vec(std::size_t count) {
        std::vector<T> res(count);
        for (auto& r : res) r = verifier_message<T>();
        return res;
    }

    // 消费 ProverState, 提取最终 Proof (仅移动)
    Proof proof() && { return {std::move(narg_string_), std::move(hints_)}; }

    const std::vector<std::uint8_t>& narg_string() const { return narg_string_; }
    DuplexSponge& sponge() { return *sponge_; }

private:
    std::unique_ptr<DuplexSponge> sponge_;
    std::vector<std::uint8_t> narg_string_;
    std::vector<std::uint8_t> hints_;
};

// ===========================================================================
// VerifierState — Fiat-Shamir 验证者状态 (确定性重放)
//
// 验证者无需随机性 — 所有字节来自证明。
// 模式: 从 narg_string 反序列化 → 吸收海绵 → 挤压挑战。
// 由于吸收顺序和数据与证明者一致, 海绵状态同步, 挤压结果相同。
//
// 与 ProverState 的对称性:
//   ProverState                       VerifierState
//   ──────────────────────────────────────────────────
//   prover_message(msg)               prover_message(out)   [反序列化]
//   verifier_message<T>()             verifier_message<T>() [挤压, 相同状态]
//   prover_hint(hint)                 prover_hint(out)      [反序列化]
//   proof() &&                        from_ds(ds, inst, proof)
//   (自动生成)                        check_eof()           [额外: 防截断]
//
// check_eof() 验证证明被完全消费 — 残留字节表示截断或注入 (可延展性攻击)。
// ===========================================================================

class VerifierState {
public:
    using Proof = ProverState::Proof;

    VerifierState() : sponge_(std::make_unique<Shake128DuplexSponge>()) {}

    // 从 DomainSeparator + Proof 构造: 吸收 ds, 将证明加载到读取缓冲区
    template <typename I>
    static VerifierState from_ds(const DomainSeparator& ds, const I& instance,
                                  const Proof& proof) {
        VerifierState vs;
        ds.absorb_into(*vs.sponge_, instance);
        vs.narg_string_ = proof.narg_string;
        vs.hints_ = proof.hints;
        return vs;
    }

    // 反序列化一条证明者消息: 从 narg_string 读取 → 吸收海绵
    // 字节不足时返回 false (证明损坏或截断)
    template <typename T>
    bool prover_message(T& out) {
        if (!narg_deserialize(out, narg_string_)) return false;
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(out, encoded);
        sponge_->absorb(encoded);
        return true;
    }

    // 批量读取 count 条消息
    template <typename T>
    bool prover_messages_vec(std::size_t count, std::vector<T>& out) {
        out.resize(count);
        for (auto& val : out)
            if (!prover_message(val)) return false;
        return true;
    }

    // 读取带外 hint (不吸收海绵, 仅反序列化)
    template <typename T>
    bool prover_hint(T& out) {
        return narg_deserialize(out, hints_);
    }

    // 吸收公开消息 (与 prover 一致的调用, 保持海绵同步)
    template <typename T>
    void public_message(const T& message) {
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(message, encoded);
        sponge_->absorb(encoded);
    }

    // 确定性重放挑战 — 海绵状态与 prover 相同时挤压结果一致
    template <typename T>
    T verifier_message() {
        constexpr std::size_t buf_sz = decoding_buffer_size<T>();
        std::array<std::uint8_t, buf_sz> buf{};
        sponge_->squeeze(buf);
        return decode_from_bytes<T>(std::span<const std::uint8_t>{buf});
    }

    // 批量挤压 count 个挑战
    template <typename T>
    std::vector<T> verifier_message_vec(std::size_t count) {
        std::vector<T> res(count);
        for (auto& r : res) r = verifier_message<T>();
        return res;
    }

    // 验证证明被完全消费 — 防御可延展性攻击
    bool check_eof() const {
        return narg_string_.empty() && hints_.empty();
    }

    DuplexSponge& sponge() { return *sponge_; }

private:
    std::unique_ptr<DuplexSponge> sponge_;
    std::span<const std::uint8_t> narg_string_;  // 借用 proof.narg_string
    std::span<const std::uint8_t> hints_;         // 借用 proof.hints
};

} // namespace whir::transcript
