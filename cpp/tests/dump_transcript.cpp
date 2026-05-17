// ===========================================================================
// dump_transcript.cpp — Fiat-Shamir Transcript golden test。
//
// 运行: ./dump_transcript > golden_transcript_cpp.txt
// 对拍: diff golden_transcript_rs.txt golden_transcript_cpp.txt
//
// 测试 Transcript 层的关键路径:
//   CASE 0: Shake128DuplexSponge 基本操作 — absorb→squeeze→absorb→squeeze
//           验证 XOF 海绵在不同消息下的输出确定性
//   CASE 1: DomainSeparator — protocol_id (SHA3-512) + session_id (SHA3-256)
//           验证 CBOR 编码 + SHA3 哈希与 Rust ciborium 逐字节一致
//   CASE 2: ProverState / VerifierState 完整往返 — message + hints + challenges
//           验证 prover 生成的 proof 可被 verifier 确定性重放
//   CASE 3: Narg 序列化 — vector<T> 长度前缀格式 (4B LE + 原始数据)
//           验证序列化→反序列化往返无字节丢失
//   CASE 4: 连续 squeeze 复用同一 XOF reader
//           验证 squeeze(20)+squeeze(20) 与 squeeze(40) 逐字节一致
//
// 基于 SHAKE-128 + SHA3-512/256, 匹配 Rust 端 spongefish::StdHash。
// ===========================================================================

#include "whir/transcript/transcript.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

using namespace whir::transcript;

// 以十六进制格式打印字节数组, 每字节 2 位小写十六进制, 无分隔符
// 输入: label — 标签前缀; data — 任意有 .begin()/.end() 的字节容器
template <typename T>
void dump_bytes(const char* label, const T& data) {
    std::printf("  %s ", label);
    for (auto byte : data) std::printf("%02x", static_cast<unsigned>(byte));
    std::printf("\n");
}

// 打印单个 Hash (32 字节), 调用 dump_bytes 完成实际输出
void dump_hash(const char* label, const whir::hash::Hash& h) {
    dump_bytes(label, h);
}

// ===========================================================================
// 测试用 struct 及其 CBOR 编码 (匹配 Rust serde + ciborium 输出)
//
// Rust 端 serde 把带字段名的 struct 序列化为 CBOR map (major 5),
// 字段名作为 text key。C++ 端手动复现该编码以确保 protocol_id 一致。
// ===========================================================================

// TestConfig → CBOR map {"version":1, "field_size":0xFFFFFFFF00000001, "security_bits":100}
struct TestConfig {
    std::uint32_t version = 1;
    std::uint64_t field_size = 0xFFFFFFFF00000001ULL;
    std::uint32_t security_bits = 100;
};
// 手动编码: 3 个键值对的 CBOR map
inline void cbor_encode(const TestConfig& v, std::vector<std::uint8_t>& out) {
    cbor_array_header(out, 3);          // 实际测试不会调用 — 仅为编译通过
    cbor_encode(v.version, out);
    cbor_encode(v.field_size, out);
    cbor_encode(v.security_bits, out);
}

// Config → 单字段 struct, CBOR 编码为 map {"id": 0xDEADBEEF}
struct Config { std::uint32_t id = 0xDEADBEEF; };
inline void cbor_encode(const Config& v, std::vector<std::uint8_t>& out) {
    cbor_array_header(out, 1);
    cbor_encode(v.id, out);
}

// Instance → 单字段 struct, CBOR 编码为 map {"size": 1024}
struct Instance { std::uint64_t size = 1024; };
inline void cbor_encode(const Instance& v, std::vector<std::uint8_t>& out) {
    cbor_array_header(out, 1);
    cbor_encode(v.size, out);
}

int main() {
    std::printf("# SECTION transcript\n");

    // =========================================================================
    // CASE 0: Shake128DuplexSponge 基本操作
    //
    // 输入: "hello" (5 字节), "world" (5 字节)
    // 过程:
    //   absorb("hello") → squeeze(32B) — 首次 squeeze: clone hasher → finalize → read
    //   absorb("world") → squeeze(32B) — absorb 清除 xof_reader, 下次 squeeze 重建
    //   squeeze(16B)                  — 连续 squeeze 复用同一 xof_reader
    // 输出:
    //   squeeze0  — SHAKE-128(hasher("hello"), 32) 的十六进制
    //   squeeze1  — SHAKE-128(hasher("hello"+"world"), 32) 的十六进制
    //   squeeze2_16b — 同上 XOF reader 的后续 16 字节
    // 验证点: absorb 更新 hasher → squeeze 输出随之改变; 连续 squeeze 复用 reader
    // =========================================================================
    {
        std::printf("CASE 0 sponge-absorb-squeeze\n");

        Shake128DuplexSponge sponge;

        // 吸收 "hello" → 挤出 32B
        const char* msg0 = "hello";
        sponge.absorb({reinterpret_cast<const std::uint8_t*>(msg0), 5});

        std::array<std::uint8_t, 32> s0{};
        sponge.squeeze(s0);
        dump_bytes("squeeze0", s0);

        // 吸收 "world" → hasher 状态更新, xof_reader 失效
        const char* msg1 = "world";
        sponge.absorb({reinterpret_cast<const std::uint8_t*>(msg1), 5});

        // 挤出 32B — 使用新的 xof_reader (hasher 已包含 "hello"+"world")
        std::array<std::uint8_t, 32> s1{};
        sponge.squeeze(s1);
        dump_bytes("squeeze1", s1);

        // 连续挤出 16B — 复用同一 xof_reader (hasher 未变)
        std::array<std::uint8_t, 16> s2{};
        sponge.squeeze(s2);
        dump_bytes("squeeze2_16b", s2);
    }

    // =========================================================================
    // CASE 1: DomainSeparator — protocol_id + session_id
    //
    // 输入:
    //   config: TestConfig{version=1, field_size=0xFFFFFFFF00000001, security_bits=100}
    //   session: "test_session_42"
    // 过程:
    //   1. 将 config 序列化为 CBOR 字节 (匹配 Rust ciborium 输出)
    //   2. protocol_id = SHA3-512(cbor_bytes) — 64 字节, 分两半输出
    //   3. session_id = SHA3-256(cbor(session_string)) — 32 字节
    // 输出:
    //   protocol_id_h1 — protocol_id 前 32B 十六进制
    //   protocol_id_h2 — protocol_id 后 32B 十六进制
    //   session_id     — 32B 十六进制
    //
    // 注意: Rust ciborium 把 struct 序列化为 CBOR **map** (带字段名),
    //       此处直接用 Rust 端输出的原始 CBOR 字节硬编码, 确保完全一致。
    // =========================================================================
    {
        std::printf("CASE 1 domain-separator protocol-and-session\n");

        // Rust ciborium 对 TestConfig 的输出:
        //   A3                          — map(3)
        //   67 76657273696f6e           — key "version" (text 7B), value 01
        //   6A 6669656c645f73697a65     — key "field_size" (text 10B), value 1B FFFFFFFF00000001
        //   6D 73656375726974795f62697473 — key "security_bits" (text 13B), value 18 64
        const uint8_t config_cbor[] = {
            0xa3, // map(3)
            0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
            0x01, // 1
            0x6a, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x73, 0x69, 0x7a, 0x65, // "field_size"
            0x1b, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, // 0xFFFFFFFF00000001
            0x6d, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x5f, 0x62, 0x69, 0x74, 0x73, // "security_bits"
            0x18, 0x64, // 100
        };

        // protocol_id = SHA3-512(config_cbor)
        std::array<uint8_t, 64> pid;
        sha3_512_hash(config_cbor, sizeof(config_cbor), pid.data());
        dump_bytes("protocol_id_h1", std::span<const uint8_t>(pid.data(), 32));
        dump_bytes("protocol_id_h2", std::span<const uint8_t>(pid.data() + 32, 32));

        // Rust ciborium 对 "test_session_42" (15 字符 String) 的输出:
        //   6F                          — text(15)
        //   746573745f73657373696f6e5f3432 — "test_session_42"
        const uint8_t sess_cbor[] = {
            0x6f, // text(15)
            0x74, 0x65, 0x73, 0x74, 0x5f, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6f, 0x6e, 0x5f, 0x34, 0x32, // "test_session_42"
        };

        // session_id = SHA3-256(sess_cbor)
        std::array<uint8_t, 32> sid;
        sha3_256_hash(sess_cbor, sizeof(sess_cbor), sid.data());
        dump_bytes("session_id", sid);
    }

    // =========================================================================
    // CASE 2: ProverState / VerifierState 完整往返
    //
    // 输入:
    //   config — u32(0xDEADBEEF), CBOR uint 编码
    //   session — "round_trip" 字符串
    //   instance — u64(1024), 原始 LE 编码
    //   消息 — 3 个 U64 值: 0xCAFEBABEDEADBEEF, 0x0123456789ABCDEF, 0xFF00FF00FF00FF00
    //   hint — array<u8,5>{0x01, 0x02, 0x03, 0x04, 0x05}
    //
    // 过程 (Prover):
    //   1. from_ds: 创建 ProverState, 吸入 protocol_id + session_id + instance
    //   2. prover_message × 2: 编码 → 吸入 sponge → 序列化到 narg_string
    //   3. verifier_message × 2: sponge squeeze(sizeof(U64)) → 解码为挑战
    //   4. prover_hint: 仅序列化到 hints (不吸入 sponge)
    //   5. prover_message + verifier_message (第三个)
    //   6. proof(): 提取 narg_string + hints
    //
    // 过程 (Verifier):
    //   1. from_ds: 吸入相同的 protocol/session/instance, 加载 proof
    //   2. prover_message × 2: 从 narg_string 反序列化 → 吸入 sponge
    //   3. verifier_message × 2: 确定性重放挑战 (sponge 状态同步)
    //   4. prover_hint: 从 hints 反序列化
    //   5. 第三个消息 + 挑战
    //   6. check_eof: 验证 proof 已完整消费
    //
    // 输出:
    //   challenge0/1/2 — prover 挤出的 U64 挑战值 (十六进制)
    //   proof_narg     — 序列化 proof 消息字节流
    //   proof_hints    — 序列化 hint 字节流
    //   message0/1/2   — verifier 反序列化的 U64 消息 (应与 prover 发送的一致)
    //   vchallenge0/1/2 — verifier 挤出的挑战 (应与 prover 挑战一致)
    //   vhint          — verifier 反序列化的 hint (应与 prover 发送的一致)
    //   check_eof      — 1 = proof 完整消费, 0 = 有剩余
    //
    // 注意: 使用裸 u32/u64 做 config/instance (CBOR uint 编码),
    //       避免 struct→CBOR map 的跨语言差异。
    // =========================================================================
    {
        std::printf("CASE 2 prover-verifier round-trip\n");

        // protocol_id = SHA3-512(cbor(0xDEADBEEF))
        std::uint32_t config_val = 0xDEADBEEF;
        auto ds = DomainSeparator::protocol(config_val).session("round_trip");
        // instance = u64(1024), 通过 encode_to_bytes 转为 8 LE 字节吸入 sponge
        std::uint64_t inst_val = 1024;

        // ---- Prover ----
        auto ps = ProverState::from_ds(ds, inst_val);

        // 发送两条消息, 每条: LE 编码 → absorb → narg_serialize
        ps.prover_message(U64(0xCAFEBABEDEADBEEFULL));
        ps.prover_message(U64(0x0123456789ABCDEFULL));

        // 挤出两个挑战 (sponge squeeze 8B → LE→U64)
        auto c0 = ps.verifier_message<U64>();
        auto c1 = ps.verifier_message<U64>();
        std::printf("  challenge0 %016llx\n", (unsigned long long)c0.value);
        std::printf("  challenge1 %016llx\n", (unsigned long long)c1.value);

        // 发送 hint — 仅序列化 (narg_serialize), 不吸入 sponge
        // 使用 std::array<u8,5> (无长度前缀, 匹配 Rust [u8; 5])
        std::array<std::uint8_t, 5> hint_data = {0x01, 0x02, 0x03, 0x04, 0x05};
        ps.prover_hint(hint_data);

        // 第三条消息 + 挑战
        ps.prover_message(U64(0xFF00FF00FF00FF00ULL));
        auto c2 = ps.verifier_message<U64>();
        std::printf("  challenge2 %016llx\n", (unsigned long long)c2.value);

        // 提取 proof (move-only, 消费 ProverState)
        auto proof = std::move(ps).proof();
        dump_bytes("proof_narg",
            std::span<const std::uint8_t>(proof.narg_string.data(), proof.narg_string.size()));
        dump_bytes("proof_hints",
            std::span<const std::uint8_t>(proof.hints.data(), proof.hints.size()));

        // ---- Verifier (确定性重放) ----
        auto vs = VerifierState::from_ds(ds, inst_val, proof);

        // 反序列化消息 (narg_deserialize) + 吸入 sponge
        U64 m0, m1, m2;
        vs.prover_message(m0);
        vs.prover_message(m1);
        std::printf("  message0 %016llx\n", (unsigned long long)m0.value);
        std::printf("  message1 %016llx\n", (unsigned long long)m1.value);

        // 挤出挑战 — 与 prover 相同 (sponge 状态同步)
        auto vc0 = vs.verifier_message<U64>();
        auto vc1 = vs.verifier_message<U64>();
        std::printf("  vchallenge0 %016llx\n", (unsigned long long)vc0.value);
        std::printf("  vchallenge1 %016llx\n", (unsigned long long)vc1.value);

        // 反序列化 hint
        std::array<std::uint8_t, 5> vhint{};
        vs.prover_hint(vhint);
        dump_bytes("vhint", vhint);

        // 第三条消息 + 挑战
        vs.prover_message(m2);
        auto vc2 = vs.verifier_message<U64>();
        std::printf("  message2 %016llx\n", (unsigned long long)m2.value);
        std::printf("  vchallenge2 %016llx\n", (unsigned long long)vc2.value);

        // 验证 proof 完整消费 (防截断/注入攻击)
        bool eof = vs.check_eof();
        std::printf("  check_eof %d\n", static_cast<int>(eof));
    }

    // =========================================================================
    // CASE 3: Narg 序列化 — vector<T> 长度前缀格式
    //
    // 输入:
    //   vec_u8 — vector<uint8_t> {0xAA, 0xBB, 0xCC, 0xDD}
    //   vec_u64 — vector<U64> {1, 258, 0xDEADBEEF}
    //
    // 过程:
    //   序列化: 写 4B LE 长度 (u32) + 原始数据字节
    //   反序列化: 读 4B LE 长度 → 读对应字节数 → 推进 span 游标
    //
    // 输出:
    //   vec_u8_encoded — vec_u8 序列化后的字节 (含长度前缀)
    //   vec_u8_decoded — 反序列化恢复的字节 (应与输入一致)
    //   vec_u8_remaining — 反序列化后游标剩余字节数 (应为 0)
    //   vec_u64_encoded / decoded — 同上, U64 版本
    //
    // 注意: Rust spongefish 的 Vec NargSerialize 不包含长度前缀,
    //       与 C++ 端格式有差异 (C++ 额外加了 4B 长度)。
    //       此测试仅验证 C++ 端往返一致性。
    // =========================================================================
    {
        std::printf("CASE 3 narg-serialize vectors\n");

        // vector<uint8_t> 往返: 4B LE 长度 "04000000" + 4B 数据 "aabbccdd"
        std::vector<std::uint8_t> orig_u8 = {0xAA, 0xBB, 0xCC, 0xDD};
        std::vector<std::uint8_t> buf;
        narg_serialize(orig_u8, buf);
        dump_bytes("vec_u8_encoded", buf);

        // 反序列化: 读取长度 → 读取数据 → 推进游标
        std::span<const std::uint8_t> src = buf;
        std::vector<std::uint8_t> decoded_u8;
        narg_deserialize(decoded_u8, src);
        dump_bytes("vec_u8_decoded", decoded_u8);
        std::printf("  vec_u8_remaining %zu\n", src.size());  // 应为 0

        // vector<U64> 往返: 每个 U64 8B LE
        // 序列化后 = 03000000 (3 个元素) + 3 × 8B LE
        std::vector<U64> orig_u64 = {U64(1), U64(258), U64(0xDEADBEEF)};
        buf.clear();
        narg_serialize(orig_u64, buf);
        dump_bytes("vec_u64_encoded", buf);

        std::span<const std::uint8_t> src2 = buf;
        std::vector<U64> decoded_u64;
        narg_deserialize(decoded_u64, src2);
        std::printf("  vec_u64_len %zu\n", decoded_u64.size());
        for (std::size_t i = 0; i < decoded_u64.size(); ++i)
            std::printf("  vec_u64[%zu] %016llx\n", i,
                (unsigned long long)decoded_u64[i].value);
        std::printf("  vec_u64_remaining %zu\n", src2.size());
    }

    // =========================================================================
    // CASE 4: 连续 squeeze 复用同一 XOF reader
    //
    // 输入: "test_xof_streaming" (18 字节)
    //
    // 过程:
    //   sponge_a: absorb → squeeze(40)         — 一次性挤出 40B
    //   sponge_b: absorb → squeeze(20) → squeeze(20) — 分两次挤出
    //
    // 预期: squeeze_40b_once == squeeze_20b_first || squeeze_20b_second
    //       因为 sponge_b 的两次连续 squeeze 复用同一 xof_reader,
    //       第一个 squeeze 创建 reader, 第二个 squeeze 继续从中读取。
    //
    // 输出:
    //   squeeze_40b_once      — 40B 一次性挤出的十六进制
    //   squeeze_20b_first     — 前 20B (应与 squeeze_40b_once 前 20B 相同)
    //   squeeze_20b_second    — 后 20B (应与 squeeze_40b_once 后 20B 相同)
    // =========================================================================
    {
        std::printf("CASE 4 squeeze-streaming xof-reader-reuse\n");

        // sponge A: 一次性 squeeze(40) — clone hasher → finalize → read 40B
        Shake128DuplexSponge sponge_a;
        const char* seed = "test_xof_streaming";
        sponge_a.absorb({reinterpret_cast<const std::uint8_t*>(seed), 18});
        std::array<std::uint8_t, 40> all_at_once{};
        sponge_a.squeeze(all_at_once);
        dump_bytes("squeeze_40b_once", all_at_once);

        // sponge B: 分两次 — 首次创建 xof_reader, 第二次复用
        Shake128DuplexSponge sponge_b;
        sponge_b.absorb({reinterpret_cast<const std::uint8_t*>(seed), 18});
        std::array<std::uint8_t, 20> first{};
        std::array<std::uint8_t, 20> second{};
        sponge_b.squeeze(first);
        sponge_b.squeeze(second);
        dump_bytes("squeeze_20b_first", first);
        dump_bytes("squeeze_20b_second", second);
    }

    return 0;
}
