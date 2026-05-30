// ===========================================================================
// dump_irs_commit.cpp — IRS 承诺协议 golden test。
//
// 运行: ./dump_irs_commit > golden_irs_cpp.txt
// 对拍: diff golden_irs_rs.txt golden_irs_cpp.txt
//
// 测试内容:
//   CASE 0: interleaved_rs_encode — NTT RS 编码, 把基域向量编码为码字矩阵
//   CASE 1: commit_leaves — 逐行 LE 编码 + SHA-256 哈希, 得到叶子哈希列表
//   CASE 2: 完整协议 — commit → open → verify 往返
//
// 输入 (通过 LCG 确定性生成, seed=0xDEADBEEFCAFEBABE):
//   - 1 个基域向量, 长度 4 (Goldilocks 域元素)
//   - interleaving_depth = 1, codeword_length = 8, rate = 4/8 = 0.5
//   - in_domain_samples = 2, out_domain_samples = 1
//   - 哈希引擎: SHA-256
//
// 输出:
//   CASE 0: 编码矩阵 matrix — 8 行 × 1 列的 Goldilocks 元素 (LE u64 十进制)
//   CASE 1: leaf-hashes — 8 个 32 字节 SHA-256 哈希值 (连续十六进制)
//   CASE 2:
//     - witness_matrix: commit 返回的编码矩阵
//     - ood_points / ood_matrix: 域外采样点及求值
//     - indomain_points / indomain_matrix: 域内挑战点及被挑战行的值
//     - proof_narg: 序列化 proof (消息字节流)
//     - proof_hints: 序列化 hints (子矩阵 + Merkle 路径)
//     - v_* : verifier 端接收并验证的对应值 (应与 prover 一致)
//     - check_eof: 1 = proof 完整消费, 0 = 有剩余字节
//
// 参数与 Rust examples/dump_irs.rs 一致。
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/embedding.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/mod_ntt.hpp"
#include "whir/algebra/ntt/utils.hpp"
#include "whir/algebra/utilities.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/irs_commit.hpp"
#include "whir/protocols/matrix_commit.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/transcript/transcript.hpp"

#include <cstdint>
#include <cstdio>
#include <vector>

// Goldilocks 域元素类型别名
using F = ::whir::algebra::Goldilocks;

// =============================================================================
// LCG — 线性同余伪随机数生成器, 与 Rust 侧完全一致
// X_{n+1} = 6364136223846793005 * X_n + 1442695040888963407 (mod 2^64)
// 用于生成确定性的测试输入, 保证对拍结果逐字节一致。
// =============================================================================
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

// 以十六进制格式打印字节数组, 每字节 2 位小写十六进制, 无分隔符
// 输入: label — 标签前缀; data — 任意有 .begin()/.end() 的字节容器
void dump_bytes(const char* label, const auto& data) {
    std::printf("  %s ", label);
    for (auto byte : data) std::printf("%02x", static_cast<unsigned>(byte));
    std::printf("\n");
}

// 打印哈希列表: 将全部 Hash (32 字节) 拼接为连续十六进制字符串
// 输入: label — 标签前缀; hashes — Hash 数组 (每个 32 字节)
// 输出: 例如 "leaves a1b2c3... (共 len*64 个十六进制字符)"
void dump_hashes(const char* label, const std::vector<::whir::hash::Hash>& hashes) {
    std::printf("  %s ", label);
    for (auto& h : hashes)
        for (auto b : h) std::printf("%02x", static_cast<unsigned>(b));
    std::printf("\n");
}

// 打印域元素向量: 每个元素输出为十进制 u64 值 (as_canonical_u64),
// 空格分隔。匹配 Rust Field64 的 Display 格式。
// 输入: label — 标签前缀; vec — Goldilocks 元素数组
// 输出: 例如 "matrix 12345678 87654321 ..."
void dump_field_vec(const char* label, const std::vector<F>& vec) {
    std::printf("  %s", label);
    for (auto& v : vec) std::printf(" %llu", (unsigned long long)v.as_canonical_u64());
    std::printf("\n");
}

int main() {
    // ---- 初始化 ----
    // LCG seed 与 Rust 侧完全相同, 保证生成的输入向量逐元素一致
    Lcg rng(0xDEADBEEFCAFEBABEULL);

    // 协议参数: 1 个向量, 长度 4, 交错深度 1, 码字长度 8 (码率 0.5)
    const std::size_t num_vectors = 1;
    const std::size_t vector_size = 4;
    const std::size_t interleaving_depth = 1;
    const std::size_t codeword_length = 8;
    const std::size_t in_domain_samples = 2;   // 域内打开 2 行
    const std::size_t out_domain_samples = 1;   // 域外采样 1 点

    // ---- 生成确定性输入向量 ----
    // 用 LCG 逐个生成 vector_size 个 Goldilocks 域元素
    std::vector<std::vector<F>> vectors(num_vectors);
    for (auto& vec : vectors) {
        vec.resize(vector_size);
        for (auto& v : vec) v = F::from_u64(rng.next());
    }
    // 转为 span<const F> 数组 (协议接口需要的格式)
    std::vector<std::span<const F>> vec_spans;
    for (auto& vec : vectors) vec_spans.push_back(vec);

    std::printf("# SECTION irs_commit\n");
    dump_field_vec("input_vector0", vectors[0]);

    // =========================================================================
    // CASE 0: interleaved_rs_encode — NTT RS 编码
    //
    // 输入: vectors (1 个长度为 4 的 Goldilocks 向量)
    // 参数: codeword_length=8 (编码后 8 个求值点), interleaving_depth=1
    // 过程:
    //   1. 向量按 interleaving_depth 切块 (这里 depth=1, 不切)
    //   2. 零填充到 codeword_length 长度 (8-4=4 个零)
    //   3. NTT 正变换 → 频域 → 求值表示
    //   4. 转置为行优先排列 (codeword_length 行 × num_cols 列)
    // 输出: matrix — 8 行 × 1 列的 Goldilocks 元素 (行主序)
    // =========================================================================
    auto matrix = ::whir::algebra::ntt::interleaved_rs_encode<F>(
        ::whir::algebra::ntt::goldilocks_engine(), vec_spans, codeword_length, interleaving_depth);
    std::size_t num_cols = num_vectors * interleaving_depth;
    std::printf("CASE 0 rs-encoded-matrix rows=%zu cols=%zu\n", codeword_length, num_cols);
    dump_field_vec("matrix", matrix);

    // =========================================================================
    // CASE 1: commit_leaves — 叶子哈希
    //
    // 输入: matrix (8 个 Goldilocks 元素), num_cols=1
    // 过程:
    //   1. 计算每行编码字节数: message_size = encoded_size<F>() * num_cols = 8
    //   2. 把 8 个元素 LE 编码为 64 字节扁平缓冲
    //   3. SHA-256 hash_many(message_size=8, bytes, leaves):
    //      将 64 字节按 8 字节切分成 8 段, 每段独立 SHA-256 → 8 个 32B Hash
    // 输出: leaves — 8 个叶子哈希 (用于构建 Merkle 树)
    // =========================================================================
    std::size_t message_size = ::whir::protocols::matrix_commit::encoded_size<F>() * num_cols;
    ::whir::hash::Sha2 leaf_engine;
    std::vector<::whir::hash::Hash> leaves(codeword_length);
    ::whir::protocols::matrix_commit::commit_leaves<F>(leaf_engine, matrix, num_cols, leaves);
    std::printf("CASE 1 leaf-hashes msg_size=%zu\n", message_size);
    dump_hashes("leaves", leaves);

    // =========================================================================
    // CASE 2: 完整 IRS 承诺协议
    //
    // 流程:
    //   Prover 侧:
    //     commit()     — RS 编码 → 叶子哈希 → Merkle 树承诺 → 域外采样求值
    //     open()       — 域内挑战 → 提取子矩阵 → Merkle 路径打开
    //     proof()      — 提取序列化的 proof (narg_string + hints)
    //   Verifier 侧:
    //     from_ds()        — 从 DomainSeparator + proof 重建状态
    //     receive_commitment() — 接收 Merkle 根 + 域外求值
    //     verify()         — 接收子矩阵 + Merkle 路径 → 验证根匹配
    //     check_eof()      — 验证 proof 已完整消费
    //
    // 输出 (prover):
    //   witness_matrix   — commit 返回的编码矩阵 (应与 CASE 0 的 matrix 一致)
    //   ood_points       — 域外采样点 (transcript 挤出的扩展域随机值)
    //   ood_matrix       — 域外求值 (每个原始向量在每个域外点的 mixed_univariate_evaluate)
    //   indomain_points  — 域内挑战点 (generator^challenge_index)
    //   indomain_matrix  — 被挑战行的子矩阵值
    //   proof_narg       — 序列化的 narg 消息 (c0, c2, Merkle root, OOD 值)
    //   proof_hints      — 序列化的 hints (子矩阵原始数据 + Merkle 路径)
    //
    // 输出 (verifier):
    //   v_ood_points     — verifier 收到的域外采样点 (应与 prover 一致)
    //   v_ood_matrix     — verifier 收到的域外求值 (应与 prover 一致)
    //   v_indomain_points — verifier 收到的域内挑战点 (应与 prover 一致)
    //   v_indomain_matrix — verifier 收到的子矩阵值 (应与 prover 一致)
    //   check_eof        — 1 = proof 完整消费 (安全), 0 = 剩余字节 (可能被篡改)
    // =========================================================================
    std::printf("CASE 2 full-protocol\n");

    // 构造 IRS 承诺配置:
    //   Embedding = Identity<F> — 基域到自身的恒等嵌入 (域内/域外使用相同域)
    //   make_config(ENGINE_ID_SHA2, 8) — 8 叶子的 SHA-256 Merkle 树
    using Embedding = ::whir::algebra::Identity<F>;
    ::whir::protocols::irs_commit::Config<Embedding> config;
    config.num_vectors = num_vectors;
    config.vector_size = vector_size;
    config.codeword_length = codeword_length;
    config.interleaving_depth = interleaving_depth;
    config.matrix_commit_num_cols = num_cols;
    config.in_domain_samples = in_domain_samples;
    config.out_domain_samples = out_domain_samples;
    config.deduplicate_in_domain = false;
    config.matrix_commit_mt = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, codeword_length);

    // ---- DomainSeparator: 协议/会话标识 ----
    // protocol_id = SHA3-512(cbor(0xBEEF)), session_id = SHA3-256(cbor("irs_dump"))
    // 使用手动 CBOR 字节以确保与 Rust 端完全一致
    ::whir::transcript::DomainSeparator ds;
    {
        // cbor(0xBEEF) = 0x19 0xBE 0xEF (CBOR uint16 big-endian)
        uint8_t cbor_proto[] = {0x19, 0xBE, 0xEF};
        sha3_512_hash(cbor_proto, 3, ds.protocol_id.data());
        // cbor("irs_dump") = 0x67 "irs_dump" (CBOR text, 7 字符)
        uint8_t cbor_sess[] = {0x67, 0x69, 0x72, 0x73, 0x5F, 0x64, 0x75, 0x6D, 0x70};
        sha3_256_hash(cbor_sess, 9, ds.session_id.data());
    }

    // ---- Prover 侧 ----
    // from_ds: 创建 ProverState 并吸入 protocol_id + session_id + instance
    ::whir::transcript::Empty instance;
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);

    // commit: RS 编码 → 叶子哈希 → Merkle 树 → 域外采样
    // 返回 Witness (编码矩阵 + Merkle 见证 + 域外求值)
    auto witness = config.commit(ps, vec_spans);
    // open: 域内挑战 + 子矩阵提取 + Merkle 路径打开
    std::vector<const ::whir::protocols::irs_commit::Witness<F, F>*> wlist{&witness};
    auto in_domain_evals = config.open(ps, wlist);
    // 提取序列化 proof (消费 ProverState)
    auto proof = std::move(ps).proof();

    // Dump prover 数据
    dump_field_vec("witness_matrix", witness.matrix);
    dump_field_vec("ood_points", witness.out_of_domain.points);
    dump_field_vec("ood_matrix", witness.out_of_domain.matrix);
    dump_field_vec("indomain_points", in_domain_evals.points);
    dump_field_vec("indomain_matrix", in_domain_evals.matrix);
    dump_bytes("proof_narg", proof.narg_string);
    dump_bytes("proof_hints", proof.hints);

    // ---- Verifier 侧 ----
    // from_ds: 重建 VerifierState (吸入相同的 protocol/session/instance)
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
    // receive_commitment: 接收 Merkle 根 + 域外采样点 + 域外求值
    auto commitment = config.receive_commitment(vs);
    // verify: 接收子矩阵 hints + Merkle 路径 → 验证根匹配 → 重建求值矩阵
    std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> clist{&commitment};
    auto verifier_evals = config.verify(vs, clist);

    // Dump verifier 数据 (应与 prover 输出一致)
    dump_field_vec("v_ood_points", commitment.out_of_domain.points);
    dump_field_vec("v_ood_matrix", commitment.out_of_domain.matrix);
    dump_field_vec("v_indomain_points", verifier_evals.points);
    dump_field_vec("v_indomain_matrix", verifier_evals.matrix);
    // check_eof = true 表示 proof 字节已完整消费 (无截断/注入)
    std::printf("  check_eof %d\n", static_cast<int>(vs.check_eof()));

    return 0;
}
