#pragma once

// ===========================================================================
// transcript.hpp — Fiat-Shamir Transcript 包装层
// 对应 WHIR 中的 src/transcript/mod.rs。
//
// 用 SHAKE-128 实现 XOF 双工海绵 (对标 spongefish::XOF<Shake128> = StdHash),
// 确保与 Rust 端字节兼容。
//
// 海绵模式 (对标 spongefish instantiations/xof.rs):
//   absorb(data)  — shake128_absorb: 把数据喂入 SHAKE-128 hasher
//   squeeze(out)  — shake128_xof_clone + shake128_xof_read: clone → finalize_xof → read
//   ratchet()     — 空操作 (Rust 的 XOF 也同样是 todo!(), WHIR 协议中不调用)
//
// DomainSeparator (对标 Rust DomainSeparator):
//   protocol_id = SHA3-512(cbor(config))     — 64B
//   session_id  = SHA3-256(cbor(session))    — 32B
//
// 核心类型:
//   DuplexSponge          — 双工海绵抽象接口
//   Shake128DuplexSponge  — SHAKE-128 实现 (对标 Rust 的 spongefish::StdHash)
//   DomainSeparator       — 协议/会话/实例三元组 (防跨协议攻击)
//   ProverState           — 证明者 proof 生成状态
//   VerifierState         — 验证者 proof 消费状态 (确定性重放)
//   Empty / U64           — Codec 辅助类型 (对应 Rust codecs.rs)
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
// 对标 spongefish::XOF<sha3::Shake128> (即 StdHash).
// Rust 端代码:
//   fn absorb(&mut self, input: &[u8]) { self.hasher.update(input); }
//   fn squeeze(&mut self, output: &mut [u8]) {
//       self.xof_reader.get_or_insert_with(|| self.hasher.clone().finalize_xof())
//           .read(output);
//   }
//
// C++ 端:
//   absorb  → shake128_absorb(hasher, input)
//   squeeze → clone hasher, 然后 shake128_xof_clone + shake128_xof_read
//   ratchet → 空操作 (Rust 的 XOF ratchet 也标了 todo!())
//
// 关键: squeeze 每次调用都会 clone 原始 hasher → finalize → read,
//       这意味着连续 squeeze(1); squeeze(1) 产生的结果不等同于 squeeze(2)!
//       这与 Rust 的 XOF 实现完全一致: 每次 squeeze 都会重新构建 xof_reader.
// ===========================================================================

//基于SHAKE-128的双工海绵状态机
class Shake128DuplexSponge final : public DuplexSponge {
public:
    Shake128DuplexSponge() { shake128_init(&hasher_); }

    void absorb(std::span<const std::uint8_t> input) override {
        // Rust: self.xof_reader = None; self.hasher.update(input);
        has_xof_ = false; //一旦有新数据,has_xof_就失效
        if (!input.empty())
            shake128_absorb(&hasher_, input.data(), input.size());
    }

    void squeeze(std::span<std::uint8_t> output) override {
        if (output.empty()) return;
        // Rust: self.xof_reader.get_or_insert_with(|| self.hasher.clone().finalize_xof())
        // 首次 squeeze 时 clone hasher → finalize_xof; 后续 squeeze 复用同一 reader。
        //如果has_xof_为false(吸收完后第一次挤出)
        if (!has_xof_) {
            xof_reader_ = shake128_xof_clone(&hasher_); //clone一份hasher_成xof_reader_
            has_xof_ = true;
        }
        shake128_xof_read(&xof_reader_, output.data(), output.size()); //xof_reader_挤出size大小数据到output
    }

    void ratchet() override {
        // Rust 的 XOF ratchet 标了 todo!(), WHIR 协议中不调用。
    }

    //深度拷贝
    std::unique_ptr<DuplexSponge> clone() const override {
        auto c = std::make_unique<Shake128DuplexSponge>();
        c->hasher_ = hasher_;
        c->has_xof_ = has_xof_;
        c->xof_reader_ = xof_reader_;
        return c;
    }

    //hash工具
    static void shake128_hash(const std::uint8_t* data, std::size_t len,
                               std::span<std::uint8_t> out) {
        shake128_ctx ctx;
        shake128_init(&ctx); //初始化
        shake128_absorb(&ctx, data, len); //吸收
        shake128_ctx xof = shake128_xof_clone(&ctx); //clone
        shake128_xof_read(&xof, out.data(), out.size()); //挤出
    }
    //
    static void sha3_256_digest(const std::uint8_t* data, std::size_t len,
                                 std::array<std::uint8_t, 32>& out) {
        sha3_256_hash(data, len, out.data()); //输出256位
    }

    static void sha3_512_digest(const std::uint8_t* data, std::size_t len,
                                 std::array<std::uint8_t, 64>& out) {
        sha3_512_hash(data, len, out.data()); //输出512位
    }

private:
    shake128_ctx hasher_;       // SHAKE-128 累积吸收状态
    shake128_ctx xof_reader_;   // XOF 挤出 reader (clone + finalized)
    bool has_xof_ = false;      // xof_reader_ 是否有效
};

// ===========================================================================
// 最小 CBOR 编码 — 用于 DomainSeparator 匹配 Rust 的 ciborium::into_writer
//
// CBOR (RFC 7049, Concise Binary Object Representation) 是 IETF 标准化的二进制
// 序列化格式。Rust 端通过 serde + ciborium 把 config/session 序列化为 CBOR,
// 然后用 SHA3-512/256 哈希得到 domain separator 的 protocol_id / session_id。
//
// C++ 端必须生成完全相同的 CBOR 字节, 否则 protocol_id 不同, 两端的海绵状态
// 从一开始就分叉, 后续所有 challenge 全部不一致。
//
// CBOR 数据结构 = 1 字节头 (高 3 位 major type + 低 5 位附加信息) + 可选长度 + 载荷:
//   Major 0 (uint):   0x00..0x17 (值 0-23 直接嵌入低 5 位)
//                     0x18 + u8, 0x19 + u16 BE, 0x1A + u32 BE, 0x1B + u64 BE
//   Major 2 (bytes):  0x40..0x57 (0-23B), 0x58 + u8, 0x59 + u16 BE
//   Major 3 (text):   0x60..0x77, 0x78 + u8, 0x79 + u16 BE, 0x7A + u32 BE
//   Major 4 (array):  0x80..0x97, 0x98 + u8, 0x99 + u16 BE, 0x9A + u32 BE
//   Major 5 (map):    0xA0..0xB7, 0xB8 + u8, ...
//
// 整数和长度一律大端 (RFC 7049 Section 2.1) — 这是常见的错误来源。
//
// 注意: Rust 的 ciborium + serde 把 struct 序列化为 CBOR **map** (major 5,
// 字段名作为 text key), 而非 array (major 4)。这意味着要精确匹配 Rust 输出,
// 每个 C++ struct 需要手写 cbor_encode 特化 (参照 Rust 端输出的 CBOR 字节)。
// 本文件只提供了简单类型 (uint/string/array) 的基础编码, 供测试使用。
// ===========================================================================

// 写单个 CBOR 无符号整数 (major 0)。v > 23 时需额外长度字节, 大端序。
// 例: v=100 → 0x18 0x64; v=0xFFFFFFFF00000001 → 0x1B FF FF FF FF 00 00 00 01
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

// 辅助: 写 CBOR array 头 (n 个元素, 大端长度)
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

// struct 编码为 CBOR array, 字段用各自的特化
template <typename T>
void cbor_encode(const T& value, std::vector<std::uint8_t>& out);

// string_view → CBOR text (major 3)
inline void cbor_encode(std::string_view text, std::vector<std::uint8_t>& out) {
    cbor_write_text(out, text);
}

// 整数 → CBOR uint (major 0)
inline void cbor_encode(std::uint32_t v, std::vector<std::uint8_t>& out) {
    cbor_write_uint(out, v);
}
inline void cbor_encode(std::uint64_t v, std::vector<std::uint8_t>& out) {
    cbor_write_uint(out, v);
}

// array → CBOR array
template <typename T, std::size_t N>
void cbor_encode(const std::array<T, N>& arr, std::vector<std::uint8_t>& out) {
    cbor_array_header(out, N);
    for (const auto& e : arr) cbor_encode(e, out);
}

// vector → CBOR array
template <typename T>
void cbor_encode(const std::vector<T>& vec, std::vector<std::uint8_t>& out) {
    cbor_array_header(out, vec.size());
    for (const auto& e : vec) cbor_encode(e, out);
}

// ===========================================================================
// Narg 序列化 — proof 字符串的读写 (proof 序列化格式)
//
// Narg 串行格式是 WHIR 协议 proof 的线格式。每个 ProverState::prover_message 调用
// 会先吸收 sponge 再追加到 narg_string。verifier 按同序反序列化并吸收 sponge,
// 从而确定性地重放挑战。
//
// 平凡可拷贝类型直接按字节拷贝 (LE 平台字节序, 与 Rust zerocopy 一致)。
// vector<T> 类型加 4B LE 长度前缀后再放原始数据。
// ===========================================================================

// 默认: 平凡可拷贝类型 — reinterpret_cast 为字节, 逐字节拷贝到 dst

//把一个T value序列化成字节流
template <typename T>
void narg_serialize(const T& value, std::vector<std::uint8_t>& dst) {
    static_assert(std::is_trivially_copyable_v<T>,
        "需要为复杂类型特化 narg_serialize");
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    dst.insert(dst.end(), p, p + sizeof(T));
}

//反序列化,从字节流读出一个T value
template <typename T>
bool narg_deserialize(T& value, std::span<const std::uint8_t>& src) {
    static_assert(std::is_trivially_copyable_v<T>,
        "需要为复杂类型特化 narg_deserialize");
    if (src.size() < sizeof(T)) return false;
    std::memcpy(&value, src.data(), sizeof(T));
    src = src.subspan(sizeof(T));
    return true;
}

// vector<uint8_t> 特化: 8B LE 长度 (对标 arkworks CanonicalSerialize for Vec<T>)
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

// 通用 vector<T>: 8B LE 长度 (对标 arkworks)
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
// Encoding — 值 → 吸收字节 (送入 sponge 之前)
//
// Fiat-Shamir 变换要求所有吸入海绵的数据先编码为字节。
// encode_to_bytes 只负责编码 (不含长度前缀), 与 narg_serialize 不同:
//   - encode_to_bytes: 海绵吸收用, 不存 proof
//   - narg_serialize:  proof 序列化用, 写入 narg_string / hints
//
// 两者对基本类型编码相同 (LE 字节), 但 vector 行为不同:
//   - encode_to_bytes(vector): 逐元素拼接, 无长度前缀
//   - narg_serialize(vector):  8B LE 长度 (u64, 对标 arkworks) + 原始字节
// ===========================================================================

// 默认: 平凡可拷贝类型 → 直接 reinterpret_cast 为字节 (LE 平台字节序)
//T value编码成字节
template <typename T>
void encode_to_bytes(const T& value, std::vector<std::uint8_t>& out) {
    static_assert(std::is_trivially_copyable_v<T>);
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

//把一个数组编码为字节
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
// Decoding — 海绵挤出的字节 → 类型化的值
//
// 对标 Rust spongefish::Decoding<[u8]>:
//   - 域元素 (Goldilocks 等): 使用 rejection sampling 保证均匀分布。
//     挤出 (MODULUS_BIT_SIZE/8 + 32) * extension_degree 个字节,
//     然后调用 from_le_bytes_mod_order() 规约。
//   - 小类型 (u64, Hash 等): 直接挤出 sizeof(T) 字节做 LE 解码。
// ===========================================================================

// Decoding buffer size — 对标 Rust decoding_field_buffer_size()
// Goldilocks:     (8 + 32) * 1 = 40B
// GoldilocksExt2: (8 + 32) * 2 = 80B (40B per component)
// GoldilocksExt3: (8 + 32) * 3 = 120B
template <typename T>
constexpr std::size_t decoding_buffer_size() {
    if constexpr (std::is_same_v<T, ::whir::algebra::Goldilocks>) return 40;
    else if constexpr (std::is_same_v<T, ::whir::algebra::GoldilocksExt2>) return 80;
    else if constexpr (std::is_same_v<T, ::whir::algebra::GoldilocksExt3>) return 120;
    else return sizeof(T);
}

// Reduce x modulo p = 2^64 - 2^32 + 1 using Barrett-style reduction.
// Assumes x < p * 2^8 (fits in 72 bits → __uint128_t).
inline std::uint64_t reduce_mod_goldilocks(__uint128_t x) {
    constexpr std::uint64_t p = 0xFFFFFFFF00000001ULL;
    while (x >= p) {
        std::uint64_t q = static_cast<std::uint64_t>(x >> 64);  // ≈ x / 2^64 ≈ x / p
        __uint128_t qp = static_cast<__uint128_t>(q) * p;
        if (qp > x) { q--; qp -= p; }
        x -= qp;
    }
    return static_cast<std::uint64_t>(x);
}

// from_le_bytes_mod_order: 对标 arkworks from_le_bytes_mod_order
// 把所有字节当作 LE 大整数, 规约到 [0, p), 不转 Montgomery。
inline std::uint64_t from_le_bytes_mod_order(const std::uint8_t* data, std::size_t len) {
    __uint128_t acc = 0;
    for (std::size_t i = len; i > 0; --i) {
        acc = (acc << 8) | data[i - 1];
        acc = reduce_mod_goldilocks(acc);
    }
    return static_cast<std::uint64_t>(acc);
}

//复制data的T字节到v中
template <typename T>
T decode_from_bytes(std::span<const std::uint8_t> data) {
    static_assert(std::is_trivially_copyable_v<T>);
    assert(data.size() >= sizeof(T));
    T v;
    std::memcpy(&v, data.data(), sizeof(T));
    return v;
}

// Goldilocks 解码: 40 LE 字节 → from_le_bytes_mod_order → 转 Montgomery
// 对标 Rust spongefish Decoding<[u8]>: Repr = DecodingFieldBuffer (40B),
// decode 调用 BasePrimeField::from_le_bytes_mod_order(chunk).
template <>
inline ::whir::algebra::Goldilocks decode_from_bytes<::whir::algebra::Goldilocks>(
    std::span<const std::uint8_t> data)
{
    assert(data.size() >= 40);
    std::uint64_t v = from_le_bytes_mod_order(data.data(), 40);
    return ::whir::algebra::Goldilocks::from_u64(v);
}

template <>
inline ::whir::algebra::GoldilocksExt2 decode_from_bytes<::whir::algebra::GoldilocksExt2>(
    std::span<const std::uint8_t> data)
{
    assert(data.size() >= 80);
    auto c0 = decode_from_bytes<::whir::algebra::Goldilocks>(data.subspan(0, 40));
    auto c1 = decode_from_bytes<::whir::algebra::Goldilocks>(data.subspan(40, 40));
    return ::whir::algebra::GoldilocksExt2{c0, c1};
}

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
// Codec 辅助类型 — 对标 Rust src/transcript/codecs.rs
//
// spongefish 未给 u64 提供 NargDeserialize (只有 u32 有), 所以 WHIR 在 C++
// 和 Rust 两端都定义了 U64 包装类型。Empty 对应 Rust 的 () — 空 instance 场景。
// ===========================================================================

// Empty — 零字节编码, 用于不需要 instance 的协议实例化
struct Empty {};
inline void encode_to_bytes(const Empty&, std::vector<std::uint8_t>&) {}
inline void cbor_encode(const Empty&, std::vector<std::uint8_t>& out) {
    out.push_back(0x80);  // CBOR 空 array, 匹配 Rust serde 对空 struct 的序列化
}

// U64 — 8 字节 LE u64 包装, 对标 spongefish::codecs::U64 / whir::transcript::codecs::U64

// 用于 transcript 中读写 8 字节 LE 整数 (如 PoW nonce、挑战值等)
struct U64 {
    std::uint64_t value = 0;
    U64() = default;
    explicit U64(std::uint64_t v) : value(v) {}
};

// U64 的海绵编码: 8 字节 LE (与 Rust impl Encoding<[u8]> for U64 一致)

// 按小端序把无符号整数64位转为8字节
inline void encode_to_bytes(const U64& v, std::vector<std::uint8_t>& out) {
    for (int b = 0; b < 8; ++b)
        out.push_back(static_cast<std::uint8_t>((v.value >> (8 * b)) & 0xFFu));
}

// U64 的挑战解码: 从 sponge 挤出的 8 字节拼成 LE u64

//从小端序把data中的8字节数据拼成64位无符号整数
template <>
inline U64 decode_from_bytes<U64>(std::span<const std::uint8_t> data) {
    std::uint64_t v = 0;
    for (int b = 0; b < 8; ++b)
        v |= static_cast<std::uint64_t>(data[b]) << (8 * b);
    return U64(v);
}

// ===========================================================================
// DomainSeparator — 协议域分隔器 (防跨协议攻击)
//
// Fiat-Shamir 安全性要求不同协议/会话/实例使用完全独立的 transcript 状态。
// DomainSeparator 通过三个字段的不同组合保证:
//   protocol_id (64B) — 协议指纹: SHA3-512(cbor(config))
//                       不同协议的 config 不同 → protocol_id 不同 → challenge 不同
//   session_id  (32B) — 会话指纹: SHA3-256(cbor(session_string))
//                       同一协议的不同运行 → session_id 不同
//   instance           — 公开输入 (statement): encode_to_bytes 后吸入海绵
//                       同一会话不同实例 → sponge 状态不同 → challenge 不同
//
// 对标 Rust DomainSeparator (src/transcript/mod.rs)。
// 用法 (链式调用):
//   auto ds = DomainSeparator::protocol(config)
//               .session("test_at_line_42")
//               .absorb_into(sponge, instance);
//
// 吸入顺序 (顺序必须与 Rust 端完全一致):
//   sponge.absorb(protocol_id)   // 64B
//   sponge.absorb(session_id)    // 32B
//   sponge.absorb(encode_to_bytes(instance))
// ===========================================================================

struct DomainSeparator {
    std::array<std::uint8_t, 64> protocol_id{};  // SHA3-512(cbor(config)) — 64B
    std::array<std::uint8_t, 32> session_id{};   // SHA3-256(cbor(session)) — 32B

    // 从 C++ 配置对象生成 protocol_id (底层调用 cbor_encode → SHA3-512)
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
        cbor_encode(s, cbor_buf);                     // CBOR text 编码
        sha3_256_hash(cbor_buf.data(), cbor_buf.size(), ds.session_id.data());
        return ds;
    }

    // 把 domain separator 的全部信息吸入海绵
    // 注意: instance 用 encode_to_bytes (原始字节), 不用 CBOR。
    //       这是因为 Rust 端 spongefish 的 instance absorb 也用 Encoding<[u8]>。
    template <typename I>
    void absorb_into(DuplexSponge& sponge, const I& instance) const {
        sponge.absorb(protocol_id);    // 1. 协议标识 (64B)
        sponge.absorb(session_id);     // 2. 会话标识 (32B)
        std::vector<std::uint8_t> buf;
        encode_to_bytes(instance, buf); //把instance编码成字节放到b字节流buf中
        sponge.absorb(buf);            // 3. 公开输入 instance (变长)
    }
};

// cbor_encode for DomainSeparator itself (空结构体 → 空 CBOR array)
inline void cbor_encode(const DomainSeparator&, std::vector<std::uint8_t>& out) {
    out.push_back(0x80);
}

// 默认 fallback: 对 generic struct 未特化的, 写 CBOR byte string (major 2)
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

// struct 需要手动定义 cbor_encode 特化来覆盖上述 fallback:
//   inline void cbor_encode(const MyConfig& v, std::vector<std::uint8_t>& out) {
//       cbor_array_header(out, 2);
//       cbor_encode(v.a, out);
//       cbor_encode(v.b, out);
//   }

// ===========================================================================
// ProverState — 证明者 Fiat-Shamir 状态
//
// 管理三个并行的状态流:
//   1. sponge_       — 双工海绵 (跟踪交互的哈希链, 决定后续挑战)
//   2. narg_string_  — proof 字节流 (prover_message 按序追加)
//   3. hints_        — 带外提示 (如 Merkle 路径, 不吸入海绵, 只序列化)
//
// prover_message 的三步操作 (顺序不可改变):
//   a) encode_to_bytes → 编码为字节
//   b) sponge_->absorb  → 吸入海绵 (推进 Fiat-Shamir 状态)
//   c) narg_serialize   → 追加到 proof 字节流 (verifier 按同序读取)
//
// prover_hint 只做序列化 (不吸入海绵):
//   用途: Merkle 树证明路径等大块数据。如果吸入海绵, verifier 重放时需要
//        重新计算哈希来验证, 成本翻倍。
//
// verifier_message 从海绵挤出随机挑战:
//   调用 squeeze(sizeof(T)) 产生确定性伪随机字节, 解码为 T。
//   由于 prover 和 verifier 的海绵状态一致, 挤出结果相同 (确定性重放)。
//
// Proof 提取 (move-only):
//   auto proof = std::move(ps).proof();  // 用 && 限定, 消费后 ProverState 失效
// ===========================================================================

class ProverState {
public:
    struct Proof {
        std::vector<std::uint8_t> narg_string;  // 序列化的 prover messages
        std::vector<std::uint8_t> hints;         // 带外提示
    };

    //初始化双工海绵
    ProverState() : sponge_(std::make_unique<Shake128DuplexSponge>()) {}

    // 从 DomainSeparator 构造: 吸入 protocol_id || session_id || encode(instance)
    template <typename I>
    static ProverState from_ds(const DomainSeparator& ds, const I& instance) {
        ProverState ps;
        ds.absorb_into(*ps.sponge_, instance); //把instance吸到海绵里
        return ps;
    }

    // 发送证明者消息: encode → absorb sponge → 追加到 proof
    template <typename T>
    void prover_message(const T& message) {
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(message, encoded);    // 1. 编码message成encoded字节流
        sponge_->absorb(encoded);              // 2. 把encode吸入海绵
        narg_serialize(message, narg_string_); // 3. 把message序列化后追加到 proof
    }

    // 发送带外 hint: 仅序列化, 不吸入海绵 (实际协议中用于 Merkle 路径)
    template <typename T>
    void prover_hint(const T& hint) {
        narg_serialize(hint, hints_); //把hint序列化后放到hints_
    }

    // 吸收公开消息: 吸入海绵, 不写 proof (prover/verifier 都知道的数据)
    template <typename T>
    void public_message(const T& message) {
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(message, encoded); //公开message编码后放到encoded
        sponge_->absorb(encoded); //海绵吸入encoded
    }

    // 挤出验证者挑战: sponge.squeeze(decoding_buffer_size<T>()) → decode → T
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

    // 消费 ProverState, 提取最终的 Proof (move-only, 防止意外复制 32B+ proof)
    //返回proof字节流和hints
    Proof proof() && { return {std::move(narg_string_), std::move(hints_)}; }

    const std::vector<std::uint8_t>& narg_string() const { return narg_string_; }
    DuplexSponge& sponge() { return *sponge_; }

private:
    std::unique_ptr<DuplexSponge> sponge_;     // 双工海绵 (SHAKE-128 XOF)
    std::vector<std::uint8_t> narg_string_;    // proof 字节流
    std::vector<std::uint8_t> hints_;          // 带外提示
};

// ===========================================================================
// VerifierState — 验证者 Fiat-Shamir 状态 (确定性重放)
//
// Verifier 不需要随机数 — proof 中包含所有需要的字节。
// 工作模式: 从 narg_string 按序反序列化 → 吸入 sponge → 挤出挑战,
// 由于吸入顺序和数据和 prover 一致, sponge 状态完全同步, 挤出结果相同。
//
// 与 ProverState 的对称:
//   ProverState                       VerifierState
//   ──────────────────────────────────────────────────
//   prover_message(msg)               prover_message(out)   [反序]
//   verifier_message<T>()             verifier_message<T>() [挤出, 状态同]
//   prover_hint(hint)                 prover_hint(out)      [反序]
//   proof() &&                        from_ds(ds, inst, proof)
//   (自动生成)                        check_eof()           [额外, 防截断]
//
// check_eof() 验证 proof 已完全消费 — 如果还有剩余字节说明 proof 被截断或
// 注入了额外数据, 属于安全漏洞 (malleability attack)。
// ===========================================================================

class VerifierState {
public:
    using Proof = ProverState::Proof;

    VerifierState() : sponge_(std::make_unique<Shake128DuplexSponge>()) {}

    // 从 DomainSeparator + Proof 构造: 吸入 ds, 用 proof 填充待读缓冲区
    template <typename I>
    static VerifierState from_ds(const DomainSeparator& ds, const I& instance,
                                  const Proof& proof) {
        VerifierState vs;
        ds.absorb_into(*vs.sponge_, instance);    // 吸入 protocol_id + session_id + instance
        vs.narg_string_ = proof.narg_string;       // 引入prover的nar_string字节proof流
        vs.hints_ = proof.hints;                   //引入prover的hints
        return vs;
    }

    // 反序列化一条 prover 消息: 从 narg_string 读取 → 吸入 sponge
    // 返回 false 表示字节不足 (proof 损坏或截断)
    template <typename T>
    bool prover_message(T& out) {
        if (!narg_deserialize(out, narg_string_)) return false; //反序列化失败
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(out, encoded); //out编码成字节流encoded
        sponge_->absorb(encoded);  // 将encoded吸入海绵, 保持与 prover 状态同步
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

    // 读取带外 hint (不吸入海绵, 仅反序列化)
    template <typename T>
    bool prover_hint(T& out) {
        return narg_deserialize(out, hints_);
    }

    // 吸收公开消息 (和 prover 一致的调用, 保持 sponge 同步)
    template <typename T>
    void public_message(const T& message) {
        std::vector<std::uint8_t> encoded;
        encode_to_bytes(message, encoded);
        sponge_->absorb(encoded);
    }

    // 确定性重放挑战 — sponge 状态和 prover 相同时挤出结果相同
    template <typename T>
    T verifier_message() {
        constexpr std::size_t buf_sz = decoding_buffer_size<T>();
        std::array<std::uint8_t, buf_sz> buf{};
        sponge_->squeeze(buf);
        return decode_from_bytes<T>(std::span<const std::uint8_t>{buf});
    }

    template <typename T>
    std::vector<T> verifier_message_vec(std::size_t count) {
        std::vector<T> res(count);
        for (auto& r : res) r = verifier_message<T>();
        return res; //返回count个数
    }

    // 验证 proof 完整消费 — 防御 proof malleability (截断/注入攻击)
    bool check_eof() const {
        return narg_string_.empty() && hints_.empty();
    }

    DuplexSponge& sponge() { return *sponge_; }

private:
    std::unique_ptr<DuplexSponge> sponge_;
    std::span<const std::uint8_t> narg_string_;  // → proof.narg_string (不拥有)
    std::span<const std::uint8_t> hints_;         // → proof.hints        (不拥有)
};

} // namespace whir::transcript
    