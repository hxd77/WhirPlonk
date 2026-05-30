// =============================================================================
// demo_irs_commit.cpp — IRS 承诺协议分步演示。
//
// 运行: ./demo_irs_commit
//
// 本文件用 2 个具体例子逐步展示 IRS 承诺协议的完整流程,
// 每一步都打印中间输出并附文字说明, 帮助理解协议的数据流。
//
// 例子设计:
//   EXAMPLE 1 — 最小参数 (1 向量 × 4 系数, depth=1, codeword=8, 域内2/域外1)
//     最简单的配置, 适合追踪每个域元素的变换。
//   EXAMPLE 2 — 交错编码 (2 向量 × 8 系数, depth=2, codeword=16, 域内3/域外2)
//     展示 interleaving_depth > 1 时向量如何被切分和交织。
//
// 协议步骤 (每个 EXAMPLE 重复):
//   步骤 1: 生成确定性输入向量 (LCG, seed=0xCAFE)
//   步骤 2: interleaved_rs_encode — NTT RS 编码 → 码字矩阵
//   步骤 3: commit_leaves — 逐行 LE 编码 + SHA-256 哈希 → 叶子列表
//   步骤 4: merkle_tree::commit — 构建 Merkle 树 → 根承诺
//   步骤 5: 域外采样 — transcript 挤出随机扩展域点 → 求值
//   步骤 6: open — 域内挑战 + 子矩阵提取 + Merkle 路径
//   步骤 7: verify — verifier 端重算叶子 + 验证 Merkle 路径
// =============================================================================

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
#include <string>
#include <vector>

using F = ::whir::algebra::Goldilocks;

// ---- 工具函数 ----

// LCG 确定性伪随机数生成器
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

// 打印分隔线
void section(const char* title) {
    std::printf("\n================================================================================\n");
    std::printf("  %s\n", title);
    std::printf("================================================================================\n\n");
}

// 打印字节数组为十六进制 (32B 一行, 方便阅读)
void dump_bytes(const char* label, const auto& data) {
    std::printf("  %s (%zu bytes):\n    ", label, data.size());
    for (std::size_t i = 0; i < data.size(); ++i) {
        std::printf("%02x", static_cast<unsigned>(data[i]));
        if ((i + 1) % 32 == 0 && i + 1 < data.size()) std::printf("\n    ");
    }
    std::printf("\n");
}

// 打印哈希数组 (每个 32B 一行, 共 n 个)
void dump_hashes(const char* label, const std::vector<::whir::hash::Hash>& hashes) {
    std::printf("  %s (%zu leaves):\n", label, hashes.size());
    for (std::size_t i = 0; i < hashes.size(); ++i) {
        std::printf("    leaf[%2zu] ", i);
        for (auto b : hashes[i]) std::printf("%02x", static_cast<unsigned>(b));
        std::printf("\n");
    }
}

// 打印域元素向量 (十进制 u64, 每行最多 8 个)
void dump_field_vec(const char* label, const std::vector<F>& vec) {
    std::printf("  %s (%zu elements):\n", label, vec.size());
    for (std::size_t i = 0; i < vec.size(); ++i) {
        if (i % 8 == 0) std::printf("    [%2zu] ", i);
        std::printf(" %20llu", (unsigned long long)vec[i].as_canonical_u64());
        if ((i + 1) % 8 == 0 || i + 1 == vec.size()) std::printf("\n");
    }
}

// 打印域元素矩阵 (行优先, 指定行列数)
void dump_field_matrix(const char* label, const std::vector<F>& mat,
                       std::size_t rows, std::size_t cols) {
    std::printf("  %s (%zu x %zu):\n", label, rows, cols);
    for (std::size_t r = 0; r < rows; ++r) {
        std::printf("    row[%2zu] ", r);
        for (std::size_t c = 0; c < cols; ++c) {
            std::printf(" %20llu", (unsigned long long)mat[r * cols + c].as_canonical_u64());
        }
        std::printf("\n");
    }
}

// ---- 主函数 ----

int main() {
    std::printf("IRS 承诺协议 — 分步演示\n");
    std::printf("所有域元素以十进制 u64 打印, 哈希以连续十六进制打印\n");

    // ==========================================================================
    // EXAMPLE 1: 最小参数 — 展示协议的每一步数据变换
    // ==========================================================================
    {
        section("EXAMPLE 1: 1 向量 x 4 系数, depth=1, codeword=8, 域内2/域外1");

        // ---- 参数说明 ----
        std::printf("  参数:\n");
        std::printf("    num_vectors        = 1      (1 个原始向量)\n");
        std::printf("    vector_size        = 4      (每个向量 4 个系数)\n");
        std::printf("    interleaving_depth = 1      (不切分, 每个向量直接编码)\n");
        std::printf("    codeword_length    = 8      (编码后 8 个求值点)\n");
        std::printf("    message_length     = 4/1=4  (消息长度)\n");
        std::printf("    rate               = 4/8=0.5 (码率 50%%)\n");
        std::printf("    num_cols           = 1*1=1  (编码矩阵列数)\n");
        std::printf("    in_domain_samples  = 2      (域内抽查 2 行)\n");
        std::printf("    out_domain_samples = 1      (域外抽查 1 点)\n\n");

        Lcg rng(0xCAFE);

        const std::size_t num_vectors = 1;
        const std::size_t vector_size = 4;
        const std::size_t interleaving_depth = 1;
        const std::size_t codeword_length = 8;
        const std::size_t num_cols = num_vectors * interleaving_depth; // = 1
        const std::size_t in_domain_samples = 2;
        const std::size_t out_domain_samples = 1;

        // =====================================================================
        // 步骤 1: 生成输入向量
        // =====================================================================
        section("步骤 1/7: 生成确定性输入向量 (LCG, seed=0xCAFE)");
        std::printf("  说明: 用 LCG 伪随机数生成器产生 4 个 Goldilocks 域元素作为输入。\n");
        std::printf("        Goldilocks 域: p = 2^64 - 2^32 + 1 ≈ 1.84×10^19\n");
        std::printf("        域元素的值域为 [0, p), 由 LCG 输出 mod p 得到。\n\n");

        std::vector<std::vector<F>> vectors(num_vectors);
        for (auto& vec : vectors) {
            vec.resize(vector_size);
            for (auto& v : vec) v = F::from_u64(rng.next());
        }
        std::vector<std::span<const F>> vec_spans;
        for (auto& vec : vectors) vec_spans.push_back(vec);

        dump_field_vec("输入向量 vec[0]", vectors[0]);

        // =====================================================================
        // 步骤 2: interleaved_rs_encode — NTT RS 编码
        // =====================================================================
        section("步骤 2/7: interleaved_rs_encode — NTT RS 编码 → 码字矩阵");
        std::printf("  算法:\n");
        std::printf("    1. 把 4 个系数零填充到 8 个位置 (后 4 个为 0)\n");
        std::printf("    2. 对 8 个元素做正向 NTT (Cooley-Tukey, size=8)\n");
        std::printf("       NTT 把「系数表示」转为「求值表示」:\n");
        std::printf("       每个输出 A_k = Σ a_j · ω^{j·k}, 其中 ω 是 8 阶本原单位根\n");
        std::printf("    3. 转置为行主序 (此处 num_cols=1, 即单列)\n\n");
        std::printf("  输出: codeword_length 行 × num_cols 列的矩阵\n");
        std::printf("        每行 = 一个求值点上的值, 每列 = 一个原始向量的编码\n\n");

        auto matrix = ::whir::algebra::ntt::interleaved_rs_encode<F>(
            ::whir::algebra::ntt::goldilocks_engine(), vec_spans,
            codeword_length, interleaving_depth);

        dump_field_matrix("编码矩阵", matrix, codeword_length, num_cols);

        // =====================================================================
        // 步骤 3: commit_leaves — 逐行哈希 → 叶子列表
        // =====================================================================
        section("步骤 3/7: commit_leaves — 逐行 LE 编码 + SHA-256 → 叶子哈希");

        std::size_t message_size = ::whir::protocols::matrix_commit::encoded_size<F>() * num_cols;
        std::printf("  编码格式: Goldilocks 元素 → 8 字节 LE u64\n");
        std::printf("            num_cols=%zu, 每行 %zu 字节\n\n", num_cols, message_size);

        std::printf("  算法:\n");
        std::printf("    1. 把编码矩阵的每一行 LE 编码为 %zu 字节\n", message_size);
        std::printf("    2. SHA-256 哈希这 %zu 字节 → 32 字节叶子哈希\n", message_size);
        std::printf("    3. 共 %zu 行, 得到 %zu 个叶子\n\n", codeword_length, codeword_length);

        ::whir::hash::Sha2 leaf_engine;
        std::vector<::whir::hash::Hash> leaves(codeword_length);
        ::whir::protocols::matrix_commit::commit_leaves<F>(
            leaf_engine, matrix, num_cols, leaves);

        dump_hashes("叶子哈希列表", leaves);

        // =====================================================================
        // 步骤 4: merkle_tree::commit — 构建 Merkle 树
        // =====================================================================
        section("步骤 4/7: merkle_tree::commit — 构建 Merkle 树 → 根承诺");

        std::printf("  结构: 8 个叶子 → 补齐到 8 (=2^3) → 满二叉树, 层数 L=3\n");
        std::printf("        总节点数 = 2^4 - 1 = 15\n\n");
        std::printf("  树结构 (自底向上):\n");
        std::printf("    Layer 0 (叶子): 8 个节点 (每个 32B SHA-256)\n");
        std::printf("    Layer 1:         4 个父节点 = H(left||right)\n");
        std::printf("    Layer 2:         2 个节点\n");
        std::printf("    Layer 3 (root):  1 个节点 → 这就是「承诺」\n\n");

        auto mt_config = ::whir::protocols::merkle_tree::make_config(
            ::whir::hash::ENGINE_ID_SHA2, codeword_length);

        // 构建树但不通过 transcript (仅看结构)
        auto mt_witness_raw = ::whir::protocols::merkle_tree::build_tree(
            mt_config, leaves,
            [](::whir::EngineId) -> const ::whir::hash::HashEngine& {
                static ::whir::hash::Sha2 engine;
                return engine;
            });

        auto root_hash = ::whir::protocols::merkle_tree::tree_root(mt_witness_raw);
        std::printf("  Merkle 树根哈希 (这是 verifier 收到的「承诺」):\n    ");
        for (auto b : root_hash) std::printf("%02x", static_cast<unsigned>(b));
        std::printf("\n\n");

        std::printf("  叶子 → 根的计算示例 (前两个叶子):\n");
        std::printf("    leaf[0] = ");
        for (std::size_t b = 0; b < 8; ++b) std::printf("%02x", static_cast<unsigned>(leaves[0][b]));
        std::printf("...\n");
        std::printf("    leaf[1] = ");
        for (std::size_t b = 0; b < 8; ++b) std::printf("%02x", static_cast<unsigned>(leaves[1][b]));
        std::printf("...\n");
        std::printf("    parent[0] = H(leaf[0] || leaf[1]) — SHA-256(64 bytes) → 32 bytes\n\n");

        // =====================================================================
        // 步骤 5: 域外采样 + 求值 (使用 transcript)
        // =====================================================================
        section("步骤 5/7: 完整协议 — commit (RS编码 + Merkle + 域外采样)");

        std::printf("  从这一步开始, 通过 transcript (Fiat-Shamir) 协调 prover 和 verifier。\n");
        std::printf("  transcript 确保所有随机挑战都是确定性的 (基于之前所有消息的哈希)。\n\n");

        std::printf("  commit() 内部做:\n");
        std::printf("    a) interleaved_rs_encode (同步骤 2)\n");
        std::printf("    b) commit_leaves (同步骤 3)\n");
        std::printf("    c) merkle_tree::commit → 通过 transcript 发送 root\n");
        std::printf("    d) 域外采样: transcript 挤出 1 个扩展域随机点\n");
        std::printf("    e) mixed_univariate_evaluate: 在域外点对多项式求值\n");
        std::printf("    f) 通过 transcript 发送域外求值结果\n\n");

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

        // DomainSeparator (与 Rust 一致的 CBOR 字节)
        ::whir::transcript::DomainSeparator ds;
        {
            uint8_t cbor_proto[] = {0x19, 0xBE, 0xEF};
            sha3_512_hash(cbor_proto, 3, ds.protocol_id.data());
            uint8_t cbor_sess[] = {0x67, 0x69, 0x72, 0x73, 0x5F, 0x64, 0x75, 0x6D, 0x70};
            sha3_256_hash(cbor_sess, 9, ds.session_id.data());
        }

        ::whir::transcript::Empty instance;
        auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
        auto witness = config.commit(ps, vec_spans);

        std::printf("  -- commit() 输出 --\n\n");
        dump_field_matrix("witness.matrix (编码矩阵)",
            witness.matrix, codeword_length, num_cols);
        dump_field_vec("witness.out_of_domain.points (域外采样点)",
            witness.out_of_domain.points);
        dump_field_matrix("witness.out_of_domain.matrix (域外求值)",
            witness.out_of_domain.matrix,
            out_domain_samples, num_vectors);

        // =====================================================================
        // 步骤 6: open — 域内挑战 + 子矩阵 + Merkle 路径
        // =====================================================================
        section("步骤 6/7: open — 域内挑战 + 子矩阵提取 + Merkle 路径");

        std::printf("  open() 内部做:\n");
        std::printf("    a) transcript 挤出 %zu 个域内挑战索引 (范围 [0, %zu))\n",
            in_domain_samples, codeword_length);
        std::printf("       每个索引 i 对应求值点 generator^i (NTT 域中的第 i 个点)\n");
        std::printf("    b) 从编码矩阵中提取被挑战的行 → 子矩阵\n");
        std::printf("    c) 子矩阵作为 prover_hint 发送 (不吸入 sponge, 仅序列化到 hints)\n");
        std::printf("    d) merkle_tree::open → 发送 Merkle 路径 (sibling hashes)\n\n");

        std::vector<const ::whir::protocols::irs_commit::Witness<F, F>*> wlist{&witness};
        auto in_domain_evals = config.open(ps, wlist);

        auto proof = std::move(ps).proof();

        std::printf("  -- open() 输出 --\n\n");
        dump_field_vec("indomain_points (求值点 = generator^index)",
            in_domain_evals.points);
        dump_field_matrix("indomain_matrix (被挑战的子矩阵)",
            in_domain_evals.matrix,
            in_domain_samples, num_cols);

        std::printf("  -- proof 结构 --\n\n");
        std::printf("  proof 包含两部分:\n");
        std::printf("    narg_string: 通过 sponge 的消息流 (root, 域外点, 域外求值, 挑战索引)\n");
        std::printf("    hints:       非交互式数据 (子矩阵原始数据, Merkle 路径 sibling hashes)\n\n");
        dump_bytes("proof.narg_string", proof.narg_string);
        dump_bytes("proof.hints", proof.hints);

        // =====================================================================
        // 步骤 7: verify — verifier 端验证
        // =====================================================================
        section("步骤 7/7: verify — verifier 端接收并验证");

        std::printf("  verify() 内部做:\n");
        std::printf("    a) 从 narg_string 反序列化: Merkle root + 域外求值\n");
        std::printf("    b) transcript 挤出域外采样点 (与 prover 相同, 因为 sponge 状态同步)\n");
        std::printf("    c) transcript 挤出域内挑战索引 (同上)\n");
        std::printf("    d) 从 hints 反序列化: 子矩阵 + Merkle 路径\n");
        std::printf("    e) 对收到的子矩阵重算叶子哈希\n");
        std::printf("    f) merkle_tree::verify: 从叶子 + Merkle 路径重建 root\n");
        std::printf("                         比对重建的 root 与承诺的 root\n\n");

        auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);
        auto commitment = config.receive_commitment(vs);

        std::printf("  -- receive_commitment() 输出 --\n\n");
        std::printf("    Merkle 树根哈希: ");
        for (auto b : commitment.matrix_commitment.root)
            std::printf("%02x", static_cast<unsigned>(b));
        std::printf("\n\n");

        std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> clist{&commitment};
        auto verifier_evals = config.verify(vs, clist);

        std::printf("  -- verify() 输出 --\n\n");
        dump_field_vec("verifier 收到的域外采样点", commitment.out_of_domain.points);
        dump_field_matrix("verifier 收到的域外求值",
            commitment.out_of_domain.matrix, out_domain_samples, num_vectors);
        dump_field_vec("verifier 收到的域内挑战点", verifier_evals.points);
        dump_field_matrix("verifier 收到的子矩阵",
            verifier_evals.matrix, in_domain_samples, num_cols);

        // ---- 对比 prover / verifier ----
        section("对比: prover 发送 vs. verifier 接收");
        bool ood_points_match = (witness.out_of_domain.points == commitment.out_of_domain.points);
        bool ood_matrix_match = (witness.out_of_domain.matrix == commitment.out_of_domain.matrix);
        bool ind_points_match = (in_domain_evals.points == verifier_evals.points);
        bool ind_matrix_match = (in_domain_evals.matrix == verifier_evals.matrix);
        bool eof = vs.check_eof();

        std::printf("    域外采样点匹配:    %s\n", ood_points_match ? "YES" : "NO (错误!)");
        std::printf("    域外求值匹配:      %s\n", ood_matrix_match ? "YES" : "NO (错误!)");
        std::printf("    域内挑战点匹配:    %s\n", ind_points_match ? "YES" : "NO (错误!)");
        std::printf("    子矩阵匹配:        %s\n", ind_matrix_match ? "YES" : "NO (错误!)");
        std::printf("    proof 完整消费:    %s\n", eof ? "YES" : "NO (错误!)");
        std::printf("\n  >>> EXAMPLE 1 验证: %s <<<\n",
            (ood_points_match && ood_matrix_match && ind_points_match &&
             ind_matrix_match && eof) ? "全部通过" : "存在差异");
    }

    // ==========================================================================
    // EXAMPLE 2: 交错编码 — interleaving_depth > 1 时的行为
    // ==========================================================================
    {
        section("EXAMPLE 2: 2 向量 x 8 系数, depth=2, codeword=16, 域内3/域外2");

        std::printf("  参数:\n");
        std::printf("    num_vectors        = 2     (2 个原始向量)\n");
        std::printf("    vector_size        = 8     (每个向量 8 个系数)\n");
        std::printf("    interleaving_depth = 2     (每个向量切成 2 个块)\n");
        std::printf("    message_length     = 8/2=4 (每块 4 个系数)\n");
        std::printf("    codeword_length    = 16    (编码后 16 个求值点)\n");
        std::printf("    rate               = 4/16=0.25 (码率 25%%)\n");
        std::printf("    num_cols           = 2*2=4 (编码矩阵列数)\n");
        std::printf("    in_domain_samples  = 3     (域内抽查 3 行)\n");
        std::printf("    out_domain_samples = 2     (域外抽查 2 点)\n\n");

        std::printf("  交错编码 (interleaving) 示意图:\n");
        std::printf("    vec[0] = [a0, a1, a2, a3, a4, a5, a6, a7]\n");
        std::printf("    vec[1] = [b0, b1, b2, b3, b4, b5, b6, b7]\n");
        std::printf("    depth=2 → 每个向量切成 2 块: [a0..a3] [a4..a7]\n");
        std::printf("    展开后共 4 列:  vec0块0, vec0块1, vec1块0, vec1块1\n");
        std::printf("    每列零填充到 16 → NTT → 16 行 × 4 列的码字矩阵\n\n");

        Lcg rng(0xBEEF);

        const std::size_t num_vectors2 = 2;
        const std::size_t vector_size2 = 8;
        const std::size_t depth2 = 2;
        const std::size_t codeword2 = 16;
        const std::size_t num_cols2 = num_vectors2 * depth2; // = 4
        const std::size_t in_samples2 = 3;
        const std::size_t out_samples2 = 2;

        // ---- 步骤 1: 生成输入 ----
        section("步骤 1/7: 生成输入向量");
        std::vector<std::vector<F>> vectors2(num_vectors2);
        for (auto& vec : vectors2) {
            vec.resize(vector_size2);
            for (auto& v : vec) v = F::from_u64(rng.next());
        }
        std::vector<std::span<const F>> vec_spans2;
        for (auto& vec : vectors2) vec_spans2.push_back(vec);

        for (std::size_t i = 0; i < num_vectors2; ++i) {
            std::string label = "输入向量 vec[" + std::to_string(i) + "]";
            dump_field_vec(label.c_str(), vectors2[i]);
        }
        std::printf("  解读: 每个向量有 8 个系数, 第 0~3 个属于块 0, 第 4~7 个属于块 1。\n\n");

        // ---- 步骤 2: 编码 ----
        section("步骤 2/7: interleaved_rs_encode — NTT RS 编码");
        auto matrix2 = ::whir::algebra::ntt::interleaved_rs_encode<F>(
            ::whir::algebra::ntt::goldilocks_engine(), vec_spans2, codeword2, depth2);

        dump_field_matrix("编码矩阵 (16 行 × 4 列)", matrix2, codeword2, num_cols2);
        std::printf("  解读:\n");
        std::printf("    每行 = 1 个求值点在 4 列上的值\n");
        std::printf("    行索引 = 求值点编号 (0~15 对应 generator^0 到 generator^15)\n");
        std::printf("    列 0 = vec[0]块0 的编码, 列 1 = vec[0]块1 的编码,\n");
        std::printf("    列 2 = vec[1]块0 的编码, 列 3 = vec[1]块1 的编码\n\n");

        // ---- 步骤 3: 叶子哈希 ----
        section("步骤 3/7: commit_leaves — 逐行哈希");
        std::size_t ms2 = ::whir::protocols::matrix_commit::encoded_size<F>() * num_cols2;
        std::printf("  每行 %zu 个域元素 × 8 字节 = %zu 字节 → SHA-256 → 32B 叶子\n\n",
            num_cols2, ms2);

        ::whir::hash::Sha2 leaf_engine2;
        std::vector<::whir::hash::Hash> leaves2(codeword2);
        ::whir::protocols::matrix_commit::commit_leaves<F>(
            leaf_engine2, matrix2, num_cols2, leaves2);

        dump_hashes("叶子哈希列表 (16 个叶子, 各 32B)", leaves2);

        // ---- 步骤 4: Merkle 树 ----
        section("步骤 4/7: Merkle 树");
        auto mt_config2 = ::whir::protocols::merkle_tree::make_config(
            ::whir::hash::ENGINE_ID_SHA2, codeword2);
        auto mt_raw2 = ::whir::protocols::merkle_tree::build_tree(
            mt_config2, leaves2,
            [](::whir::EngineId) -> const ::whir::hash::HashEngine& {
                static ::whir::hash::Sha2 engine;
                return engine;
            });
        auto root2 = ::whir::protocols::merkle_tree::tree_root(mt_raw2);

        std::printf("  16 个叶子 → 补齐到 16 (=2^4) → 满二叉树, L=4 层, 共 31 个节点\n\n");
        std::printf("  Merkle 树根哈希: ");
        for (auto b : root2) std::printf("%02x", static_cast<unsigned>(b));
        std::printf("\n\n");

        // ---- 步骤 5: 完整 commit ----
        section("步骤 5/7: commit — 完整协议");
        using Embedding2 = ::whir::algebra::Identity<F>;
        ::whir::protocols::irs_commit::Config<Embedding2> config2;
        config2.num_vectors = num_vectors2;
        config2.vector_size = vector_size2;
        config2.codeword_length = codeword2;
        config2.interleaving_depth = depth2;
        config2.matrix_commit_num_cols = num_cols2;
        config2.in_domain_samples = in_samples2;
        config2.out_domain_samples = out_samples2;
        config2.deduplicate_in_domain = false;
        config2.matrix_commit_mt = mt_config2;

        ::whir::transcript::DomainSeparator ds2;
        {
            uint8_t cbor_proto[] = {0x19, 0xBE, 0xEF};
            sha3_512_hash(cbor_proto, 3, ds2.protocol_id.data());
            uint8_t cbor_sess[] = {0x6E, 0x64, 0x65, 0x6D, 0x6F, 0x5F, 0x65, 0x78,
                                    0x61, 0x6D, 0x70, 0x6C, 0x65, 0x5F, 0x32};
            sha3_256_hash(cbor_sess, 15, ds2.session_id.data());
        }

        ::whir::transcript::Empty inst2;
        auto ps2 = ::whir::transcript::ProverState::from_ds(ds2, inst2);
        auto witness2 = config2.commit(ps2, vec_spans2);

        std::printf("  -- commit() 输出 --\n\n");
        dump_field_vec("域外采样点 (2 个扩展域点)", witness2.out_of_domain.points);
        std::printf("  说明: 域外采样点不在 {generator^0..generator^15} 中,\n");
        std::printf("        而是 transcript 从扩展域挤出的完全随机的点。\n");
        std::printf("        对每个原始向量在每个域外点求值: 2 点 × 2 向量 = 4 个扩展域值\n\n");
        dump_field_matrix("域外求值矩阵 (2 行 × 2 列)",
            witness2.out_of_domain.matrix, out_samples2, num_vectors2);
        std::printf("  解读: row[i] = 域外点 i 上各向量的求值; col[j] = 向量 j 在各域外点的求值\n\n");

        // ---- 步骤 6: open ----
        section("步骤 6/7: open — 域内挑战");
        std::vector<const ::whir::protocols::irs_commit::Witness<F, F>*> wlist2{&witness2};
        auto in_domain_evals2 = config2.open(ps2, wlist2);
        auto proof2 = std::move(ps2).proof();

        dump_field_vec("域内挑战点 (3 个)", in_domain_evals2.points);
        std::printf("  说明: 每个挑战点 = generator^(随机索引)\n");
        std::printf("        这些点在 NTT 域内, 对应编码矩阵的某一行。\n\n");
        dump_field_matrix("被挑战的子矩阵 (3 行 × 4 列)",
            in_domain_evals2.matrix, in_samples2, num_cols2);
        std::printf("  解读: 第 pi 行 = 编码矩阵中第 challenge_index[pi] 行的完整内容。\n");
        std::printf("        verifier 将检查这些值是否与 Merkle 承诺一致。\n\n");
        dump_bytes("proof.narg_string", proof2.narg_string);
        dump_bytes("proof.hints", proof2.hints);

        // ---- 步骤 7: verify ----
        section("步骤 7/7: verify — verifier 端验证");
        auto vs2 = ::whir::transcript::VerifierState::from_ds(ds2, inst2, proof2);
        auto commitment2 = config2.receive_commitment(vs2);
        std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> clist2{&commitment2};
        auto verifier_evals2 = config2.verify(vs2, clist2);

        std::printf("  -- verifier 端收到的数据 --\n\n");
        dump_field_vec("收到的域外采样点", commitment2.out_of_domain.points);
        dump_field_vec("收到的域内挑战点", verifier_evals2.points);

        // 对比
        section("对比: prover vs. verifier");
        bool ok = true;
        ok &= (witness2.out_of_domain.points == commitment2.out_of_domain.points);
        ok &= (witness2.out_of_domain.matrix == commitment2.out_of_domain.matrix);
        ok &= (in_domain_evals2.points == verifier_evals2.points);
        ok &= (in_domain_evals2.matrix == verifier_evals2.matrix);
        ok &= vs2.check_eof();

        std::printf("    域外采样点: %s\n",
            witness2.out_of_domain.points == commitment2.out_of_domain.points ? "一致" : "不一致!");
        std::printf("    域外求值:   %s\n",
            witness2.out_of_domain.matrix == commitment2.out_of_domain.matrix ? "一致" : "不一致!");
        std::printf("    域内挑战点: %s\n",
            in_domain_evals2.points == verifier_evals2.points ? "一致" : "不一致!");
        std::printf("    子矩阵:     %s\n",
            in_domain_evals2.matrix == verifier_evals2.matrix ? "一致" : "不一致!");
        std::printf("    proof 完整: %s\n", vs2.check_eof() ? "是" : "否!");
        std::printf("\n  >>> EXAMPLE 2 验证: %s <<<\n", ok ? "全部通过" : "存在差异");
    }

    std::printf("\n================================================================================\n");
    std::printf("  演示结束。\n");
    std::printf("================================================================================\n\n");

    return 0;
}
