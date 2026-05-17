// =============================================================================
// demo_open_verify.cpp — 深入追踪 open() 和 verify() 的内部变量。
//
// 运行: ./demo_open_verify
//
// 用最简单的参数 (1 向量×4 系数, depth=1, codeword=8, 域内2/域外1)
// 把 open() 和 verify() 内部的每一个中间变量都打印出来。
// =============================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/embedding.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/mod_ntt.hpp"
#include "whir/algebra/utilities.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/irs_commit.hpp"
#include "whir/protocols/matrix_commit.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/protocols/challenge_indices.hpp"
#include "whir/transcript/transcript.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using F = ::whir::algebra::Goldilocks;

// ---- 工具 ----
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

void hr(const char* title = nullptr) {
    if (title) std::printf("\n=== %s ===\n\n", title);
    else std::printf("--------------------------------------------------\n");
}

void dump_bytes_raw(const char* label, const auto& data) {
    std::printf("  %s (%zu bytes): ", label, data.size());
    for (auto b : data) std::printf("%02x", static_cast<unsigned>(b));
    std::printf("\n");
}

void dump_hash(const char* label, const ::whir::hash::Hash& h) {
    std::printf("  %s: ", label);
    for (auto b : h) std::printf("%02x", static_cast<unsigned>(b));
    std::printf("\n");
}

void dump_field(const char* label, const F& v) {
    std::printf("  %s: %20llu\n", label, (unsigned long long)v.as_canonical_u64());
}

void dump_field_vec(const char* label, const std::vector<F>& vec) {
    std::printf("  %s (%zu elements):\n", label, vec.size());
    for (std::size_t i = 0; i < vec.size(); ++i)
        std::printf("    [%2zu] %20llu\n", i, (unsigned long long)vec[i].as_canonical_u64());
}

void dump_indices(const char* label, const std::vector<std::size_t>& indices) {
    std::printf("  %s (%zu indices): [", label, indices.size());
    for (std::size_t i = 0; i < indices.size(); ++i) {
        if (i > 0) std::printf(", ");
        std::printf("%zu", indices[i]);
    }
    std::printf("]\n");
}

// 打印完整的 Merkle 树结构
void dump_mt_layers(const ::whir::protocols::merkle_tree::Config& cfg,
                     const ::whir::protocols::merkle_tree::Witness& w) {
    std::size_t L = cfg.layers.size();
    std::size_t leaf_len = std::size_t{1} << L;
    std::size_t off = 0, len = leaf_len;
    for (std::size_t layer = 0; layer <= L; ++layer) {
        std::printf("  Layer %zu (%s, %zu nodes):\n",
            layer, layer == 0 ? "叶子" : (layer == L ? "root" : "内部"), len);
        for (std::size_t i = 0; i < len && i < 4; ++i) {
            std::printf("    node[%2zu] ", i);
            for (std::size_t b = 0; b < 8; ++b)
                std::printf("%02x", static_cast<unsigned>(w.nodes[off + i][b]));
            std::printf("...\n");
        }
        if (len > 4) std::printf("    ... (还有 %zu 个节点省略)\n", len - 4);
        off += len;
        len /= 2;
    }
}

int main() {
    std::printf("open() / verify() 内部变量逐步追踪\n");
    std::printf("========================================\n");

    // ---- 参数 ----
    const std::size_t num_vectors = 1;
    const std::size_t vector_size = 4;
    const std::size_t interleaving_depth = 1;
    const std::size_t codeword_length = 8;   // 2^3
    const std::size_t num_cols = num_vectors * interleaving_depth; // = 1
    const std::size_t in_domain_samples = 2;
    const std::size_t out_domain_samples = 1;

    std::printf("参数: 1向量×4系数, depth=1, codeword=%zu, num_cols=%zu, 域内=%zu, 域外=%zu\n\n",
        codeword_length, num_cols, in_domain_samples, out_domain_samples);

    // ---- 构造输入 ----
    Lcg rng(0xCAFE);
    std::vector<std::vector<F>> vectors(num_vectors);
    for (auto& vec : vectors) {
        vec.resize(vector_size);
        for (auto& v : vec) v = F::from_u64(rng.next());
    }
    std::vector<std::span<const F>> vec_spans;
    for (auto& vec : vectors) vec_spans.push_back(vec);

    // ---- 编码矩阵 ----
    auto matrix = ::whir::algebra::ntt::interleaved_rs_encode<F>(
        ::whir::algebra::ntt::goldilocks_engine(), vec_spans,
        codeword_length, interleaving_depth);

    hr("编码矩阵 (8 行 × 1 列, 行主序)");
    std::printf("  每行 = 一个 NTT 求值点上的值, 行索引 0~7 对应 generator^0~generator^7\n\n");
    for (std::size_t r = 0; r < codeword_length; ++r) {
        std::printf("  matrix[%zu] = %20llu\n", r,
            (unsigned long long)matrix[r].as_canonical_u64());
    }

    // ---- 叶子哈希 ----
    ::whir::hash::Sha2 leaf_engine;
    std::vector<::whir::hash::Hash> leaves(codeword_length);
    ::whir::protocols::matrix_commit::commit_leaves<F>(leaf_engine, matrix, num_cols, leaves);

    // 同时计算每行的 LE 编码字节 (用于后续理解)
    std::vector<std::uint8_t> all_encoded_bytes(matrix.size() * 8);
    for (std::size_t i = 0; i < matrix.size(); ++i) {
        uint64_t v = matrix[i].as_canonical_u64();
        for (int b = 0; b < 8; ++b)
            all_encoded_bytes[i * 8 + b] = static_cast<uint8_t>((v >> (8 * b)) & 0xFF);
    }

    hr("叶子哈希列表 (每行 LE 编码 → SHA-256)");
    for (std::size_t i = 0; i < codeword_length; ++i) {
        std::printf("  row[%zu] LE编码: ", i);
        for (int b = 0; b < 8; ++b)
            std::printf("%02x", all_encoded_bytes[i * 8 + b]);
        std::printf("  →  leaf[%zu] = ", i);
        for (auto b : leaves[i]) std::printf("%02x", static_cast<unsigned>(b));
        std::printf("\n");
    }

    // ---- 构建 Merkle 树 ----
    auto mt_config = ::whir::protocols::merkle_tree::make_config(
        ::whir::hash::ENGINE_ID_SHA2, codeword_length);
    auto el = [](::whir::EngineId) -> const ::whir::hash::HashEngine& {
        static ::whir::hash::Sha2 e; return e;
    };
    auto mt_witness = ::whir::protocols::merkle_tree::build_tree(mt_config, leaves, el);
    auto root = ::whir::protocols::merkle_tree::tree_root(mt_witness);

    hr("Merkle 树完整结构 (8 叶子 → 3 层 → root)");
    std::printf("  num_leaves=%zu, L=%zu, num_nodes=%zu\n\n",
        mt_config.num_leaves, mt_config.layers.size(), mt_config.num_nodes());
    dump_mt_layers(mt_config, mt_witness);
    std::printf("  root = ");
    for (auto b : root) std::printf("%02x", static_cast<unsigned>(b));
    std::printf("\n");

    // ---- DomainSeparator ----
    ::whir::transcript::DomainSeparator ds;
    {
        uint8_t cbor_proto[] = {0x19, 0xBE, 0xEF};
        sha3_512_hash(cbor_proto, 3, ds.protocol_id.data());
        uint8_t cbor_sess[] = {0x67, 0x64, 0x65, 0x6D, 0x6F};
        sha3_256_hash(cbor_sess, 5, ds.session_id.data());
    }

    // ---- Transcript (prover 侧, 提前完成 commit) ----
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
    config.matrix_commit_mt = mt_config;

    ::whir::transcript::Empty instance;
    auto ps = ::whir::transcript::ProverState::from_ds(ds, instance);
    auto witness = config.commit(ps, vec_spans);

    // =========================================================================
    // ██████████████████████████████████████████████████████████████████████████
    // 现在进入 open() 内部逻辑, 逐步追踪
    // ██████████████████████████████████████████████████████████████████████████
    // =========================================================================

    hr("==================== open() 开始 ====================");

    // --- open() 步骤 1: 验证 witness 尺寸 ---
    hr("open() 步骤 1 — 验证所有见证的尺寸一致性");
    std::printf("  witness->matrix.size()     = %zu  (期望 %zu = codeword*num_cols)\n",
        witness.matrix.size(), config.size());
    std::printf("  witness->ood_points.size() = %zu  (期望 %zu = out_domain_samples)\n",
        witness.out_of_domain.points.size(), out_domain_samples);
    std::printf("  witness->ood_matrix.size() = %zu  (期望 %zu = ood_samples*num_vectors)\n",
        witness.out_of_domain.matrix.size(), out_domain_samples * num_vectors);

    // --- open() 步骤 2: 挤出域内挑战 ---
    hr("open() 步骤 2 — in_domain_challenges(prover_state)");

    // 手动追踪 challenge_indices 内部:
    //   1. size_bytes = ceil(log2(8)/8) = ceil(3/8) = 1
    //   2. total_bytes = count * size_bytes = 2 * 1 = 2
    //   3. 从 transcript 挤出 2 个 uint8_t
    //   4. big-endian 解码: idx[i] = entropy[i] % 8
    std::size_t size_bytes = (::whir::protocols::challenge_indices::log2_pow2(codeword_length) + 7) / 8;
    std::printf("  codeword_length=%zu → log2_pow2=%zu → size_bytes=%zu\n",
        codeword_length, ::whir::protocols::challenge_indices::log2_pow2(codeword_length), size_bytes);
    std::printf("  count=%zu → total_bytes=count*size_bytes=%zu\n\n", in_domain_samples, in_domain_samples * size_bytes);

    auto [indices, points] = config.in_domain_challenges(ps);

    std::printf("  挤出 %zu 个域内挑战索引:\n", indices.size());
    for (std::size_t pi = 0; pi < indices.size(); ++pi) {
        auto gen = config.generator();
        auto pt = gen.pow(static_cast<uint64_t>(indices[pi]));
        std::printf("    索引 indices[%zu] = %zu  →  求值点 points[%zu] = generator^%zu = %20llu\n",
            pi, indices[pi], pi, indices[pi], (unsigned long long)pt.as_canonical_u64());
        std::printf("       (这个点对应编码矩阵的第 %zu 行)\n", indices[pi]);
    }

    // --- open() 步骤 3: 提取子矩阵 ---
    hr("open() 步骤 3 — 提取被挑战的行 → 子矩阵 submatrix");

    std::size_t n_witnesses = 1;
    std::size_t stride = n_witnesses * num_cols; // = 1

    for (std::size_t wi = 0; wi < n_witnesses; ++wi) {
        std::printf("  -- Witness[%zu] --\n\n", wi);

        // 3a. 提取子矩阵
        std::vector<F> submatrix;
        submatrix.reserve(indices.size() * num_cols);

        for (std::size_t pi = 0; pi < indices.size(); ++pi) {
            std::size_t row_start = indices[pi] * num_cols; // 被挑战行的起始偏移
            std::printf("  挑战 %zu: 索引=%zu → row_start=%zu\n", pi, indices[pi], row_start);

            for (std::size_t c = 0; c < num_cols; ++c) {
                F val = witness.matrix[row_start + c];
                submatrix.push_back(val);
                std::printf("    列 %zu: matrix[%zu+%zu]=matrix[%zu] = %20llu\n",
                    c, row_start, c, row_start + c,
                    (unsigned long long)val.as_canonical_u64());
            }
        }

        std::printf("\n  提取的子矩阵 (%zu 行 × %zu 列):\n", indices.size(), num_cols);
        for (std::size_t pi = 0; pi < indices.size(); ++pi) {
            std::printf("    submatrix[%zu] = %20llu\n",
                pi, (unsigned long long)submatrix[pi].as_canonical_u64());
        }

        // 注意: 在真实 open() 中, submatrix 通过 prover_hint 发送,
        // 它只序列化到 hints 中, 不吸入 sponge。
        // 子矩阵的 LE 编码字节:
        std::printf("\n  子矩阵序列化 (LE 编码, 用于 verifier 重算叶子):\n");
        std::vector<uint8_t> submatrix_bytes(submatrix.size() * 8);
        for (std::size_t i = 0; i < submatrix.size(); ++i) {
            uint64_t v = submatrix[i].as_canonical_u64();
            for (int b = 0; b < 8; ++b)
                submatrix_bytes[i * 8 + b] = static_cast<uint8_t>((v >> (8 * b)) & 0xFF);
        }
        dump_bytes_raw("submatrix LE 编码", submatrix_bytes);
    }

    // --- open() 步骤 4: Merkle 树打开 ---
    hr("open() 步骤 4 — merkle_tree::open → open_path() 生成 Merkle 路径");

    std::printf("  open_path(config, witness, indices=[...])\n\n");
    std::printf("  Merkle 树叶子层有 %zu 个节点 (补齐到 2^%zu)\n",
        std::size_t{1} << mt_config.layers.size(), mt_config.layers.size());

    // 手动追踪 open_path 的每一步
    auto raw_indices = indices;
    {
        // 排序+去重
        std::vector<std::size_t> sorted_idx(raw_indices.begin(), raw_indices.end());
        std::sort(sorted_idx.begin(), sorted_idx.end());
        sorted_idx.erase(std::unique(sorted_idx.begin(), sorted_idx.end()), sorted_idx.end());
        dump_indices("排序去重后的索引", sorted_idx);

        std::size_t layer_off = 0;
        std::size_t layer_len = std::size_t{1} << mt_config.layers.size(); // = 8
        std::size_t layer_num = 0;

        std::vector<std::size_t> cur = sorted_idx;
        while (layer_len > 1) {
            std::printf("\n  --- Layer %zu (长度 %zu, 偏移 %zu) ---\n", layer_num, layer_len, layer_off);

            std::vector<std::size_t> next;
            next.reserve(cur.size());

            for (std::size_t k = 0; k < cur.size();) {
                std::size_t a = cur[k];
                std::size_t sibling = a ^ 1;
                bool merge = (k + 1 < cur.size()) && (cur[k + 1] == sibling);

                if (merge) {
                    std::printf("    idx=%zu: 兄弟 %zu 也在集合中 → 无需 hint, 父节点=%zu\n",
                        a, sibling, a >> 1);
                    next.push_back(a >> 1);
                    k += 2;
                } else {
                    auto& sibling_hash = mt_witness.nodes[layer_off + sibling];
                    std::printf("    idx=%zu: 兄弟 %zu 不在集合中 → 加入 hint = node[%zu] = ",
                        a, sibling, layer_off + sibling);
                    for (std::size_t b = 0; b < 8; ++b)
                        std::printf("%02x", static_cast<unsigned>(sibling_hash[b]));
                    std::printf("...\n");
                    next.push_back(a >> 1);
                    k += 1;
                }
            }
            cur = std::move(next);
            layer_off += layer_len;
            layer_len /= 2;
            layer_num++;
        }
        std::printf("\n  最终 root 索引: %zu\n", cur.empty() ? 999 : cur[0]);
    }

    // 调用真实的 open_path 获取 hints
    auto hints = ::whir::protocols::merkle_tree::open_path(mt_config, mt_witness,
        std::span<const std::size_t>{indices});
    std::printf("\n  生成的 hints (%zu 个 Hash):\n", hints.size());
    for (std::size_t i = 0; i < hints.size(); ++i) {
        std::printf("    hint[%zu] = ", i);
        for (auto b : hints[i]) std::printf("%02x", static_cast<unsigned>(b));
        std::printf("\n");
    }

    // --- open() 最终调用 ---
    hr("open() 完整调用结果");
    std::vector<const ::whir::protocols::irs_commit::Witness<F, F>*> wlist{&witness};
    auto in_domain_evals = config.open(ps, wlist);
    auto proof = std::move(ps).proof();

    dump_field_vec("返回的 points (求值点)", in_domain_evals.points);
    std::printf("\n  返回的 matrix (%zu 行 × %zu 列):\n", in_domain_evals.points.size(),
        in_domain_evals.num_columns());
    for (std::size_t r = 0; r < in_domain_evals.points.size(); ++r) {
        std::printf("    row[%zu] = %20llu\n", r,
            (unsigned long long)in_domain_evals.matrix[r].as_canonical_u64());
    }

    dump_bytes_raw("proof.narg_string", proof.narg_string);
    dump_bytes_raw("proof.hints (子矩阵 + Merkle 路径)", proof.hints);

    // =========================================================================
    // ██████████████████████████████████████████████████████████████████████████
    // 现在进入 verify() 内部逻辑, 逐步追踪
    // ██████████████████████████████████████████████████████████████████████████
    // =========================================================================

    hr("==================== verify() 开始 ====================");

    // 创建 verifier state
    auto vs = ::whir::transcript::VerifierState::from_ds(ds, instance, proof);

    // --- verify() 准备: receive_commitment ---
    auto commitment = config.receive_commitment(vs);

    hr("verify() 前置 — receive_commitment() 收到的数据");
    std::printf("  Merkle root: ");
    for (auto b : commitment.matrix_commitment.root)
        std::printf("%02x", static_cast<unsigned>(b));
    std::printf("\n  域外采样点: %zu 个\n", commitment.out_of_domain.points.size());
    std::printf("  域外求值:   %zu 个\n\n", commitment.out_of_domain.matrix.size());
    std::printf("  说明: 此时 verifier 手里的 sponge 状态与 prover 同步,\n");
    std::printf("        所以接下来的域内挑战索引将完全相同。\n");

    // --- verify() 步骤 1: 挤出域内挑战 ---
    hr("verify() 步骤 1 — in_domain_challenges(verifier_state)");
    auto [v_indices, v_points] = config.in_domain_challenges(vs);

    std::printf("  挤出 %zu 个域内挑战索引:\n", v_indices.size());
    for (std::size_t pi = 0; pi < v_indices.size(); ++pi) {
        std::printf("    v_indices[%zu] = %zu → v_points[%zu] = generator^%zu = %20llu\n",
            pi, v_indices[pi], pi, v_indices[pi],
            (unsigned long long)v_points[pi].as_canonical_u64());
    }
    std::printf("\n  与 prover 的索引比较: %s\n",
        indices == v_indices ? "完全一致 (确定性!)" : "不一致!");

    // --- verify() 步骤 2: 接收子矩阵 ---
    hr("verify() 步骤 2 — 从 hints 中反序列化子矩阵");
    {
        std::vector<F> v_submatrix;
        // 手动做 verifier_state.prover_hint(v_submatrix):
        // 这会从 proof.hints 中读取 4B LE 长度 + 原始数据
        // (先模拟一下, 因为真实调用会推进游标)
        std::printf("  verifier 从 proof.hints 中读取子矩阵:\n");
        std::printf("    格式: [4B LE 元素个数] + [每个元素 8B LE]\n");
        std::printf("    indices.size=%zu, num_cols=%zu\n", v_indices.size(), num_cols);
        std::printf("    预期元素个数 = %zu×%zu = %zu\n", v_indices.size(), num_cols,
            v_indices.size() * num_cols);
        std::printf("    预期字节数 = 4 + %zu×8 = %zu\n\n",
            v_indices.size() * num_cols, 4 + v_indices.size() * num_cols * 8);
    }

    // --- verify() 步骤 3: 重算叶子哈希 ---
    hr("verify() 步骤 3 — 对收到的子矩阵重算叶子哈希 commit_leaves()");
    {
        // 提取真实的子矩阵 (从原始的 witness.matrix 中, verifier 看到的就是这个)
        std::vector<F> v_submatrix;
        for (std::size_t pi = 0; pi < v_indices.size(); ++pi) {
            std::size_t row_start = v_indices[pi] * num_cols;
            for (std::size_t c = 0; c < num_cols; ++c)
                v_submatrix.push_back(witness.matrix[row_start + c]);
        }

        std::printf("  verifier 收到的子矩阵:\n");
        for (std::size_t i = 0; i < v_submatrix.size(); ++i)
            std::printf("    submatrix[%zu] = %20llu\n", i,
                (unsigned long long)v_submatrix[i].as_canonical_u64());

        // 重算叶子哈希
        ::whir::hash::Sha2 v_leaf_engine;
        std::vector<::whir::hash::Hash> v_leaf_hashes(v_indices.size());
        ::whir::protocols::matrix_commit::commit_leaves<F>(
            v_leaf_engine, v_submatrix, num_cols, v_leaf_hashes);

        std::printf("\n  重算的叶子哈希:\n");
        for (std::size_t i = 0; i < v_leaf_hashes.size(); ++i) {
            std::printf("    v_leaf_hash[%zu] (对应索引 %zu) = ", i, v_indices[i]);
            for (auto b : v_leaf_hashes[i]) std::printf("%02x", static_cast<unsigned>(b));
            std::printf("\n");
        }

        // 与原叶子对比
        std::printf("\n  与原始叶子哈希对比:\n");
        for (std::size_t i = 0; i < v_indices.size(); ++i) {
            bool match = (v_leaf_hashes[i] == leaves[v_indices[i]]);
            std::printf("    索引 %zu: %s\n", v_indices[i], match ? "匹配" : "不匹配 (篡改!)");
        }
    }

    // --- verify() 步骤 4: Merkle 树验证 ---
    hr("verify() 步骤 4 — merkle_tree::verify → verify_path() 逐层重建 root");

    std::printf("  输入:\n");
    std::printf("    indices = ");
    for (auto i : v_indices) std::printf("%zu ", i);
    std::printf("\n");
    std::printf("    leaf_hashes: 上面重算的 %zu 个哈希\n", v_indices.size());
    std::printf("    hints: prover 发送的 %zu 个 sibling 哈希\n\n", hints.size());

    // 手动追踪 verify_path 的每一步
    {
        // verify_path 第 1 步: 组合 (index, hash) 并排序去重
        std::vector<std::pair<std::size_t, ::whir::hash::Hash>> layer;
        for (std::size_t k = 0; k < v_indices.size(); ++k)
            layer.emplace_back(v_indices[k], leaves[v_indices[k]]);

        std::sort(layer.begin(), layer.end(),
            [](const auto& l, const auto& r) { return l.first < r.first; });

        std::printf("\n  排序后的 (index, leaf_hash) 对:\n");
        for (auto& [idx, h] : layer) {
            std::printf("    (%zu, ", idx);
            for (std::size_t b = 0; b < 8; ++b) std::printf("%02x", static_cast<unsigned>(h[b]));
            std::printf("...)\n");
        }

        // 拆分为 idx 和 hashes 两个独立数组
        std::vector<std::size_t> idx;
        std::vector<::whir::hash::Hash> hashes;
        for (auto& [i, h] : layer) { idx.push_back(i); hashes.push_back(h); }

        // 逐层重建
        std::size_t hint_cursor = 0;
        std::size_t depth = 0;
        for (auto it = mt_config.layers.rbegin(); it != mt_config.layers.rend(); ++it) {
            std::printf("\n  --- 重建 Layer %zu (从叶子往上第 %zu 层) ---\n", depth, depth);

            std::vector<std::size_t> next_indices;
            std::vector<::whir::hash::Hash> input_pairs;
            std::size_t hp = 0;

            for (std::size_t k = 0; k < idx.size();) {
                std::size_t a = idx[k];
                std::size_t sibling_idx = a ^ 1;
                bool merge = (k + 1 < idx.size()) && (idx[k + 1] == sibling_idx);

                if (merge) {
                    std::printf("    idx=%zu: 兄弟 %zu 也在集合中\n", a, sibling_idx);
                    std::printf("      left  = hash(idx=%zu), right = hash(idx=%zu)\n",
                        std::min(a, sibling_idx), std::max(a, sibling_idx));
                    input_pairs.push_back(hashes[hp + 0]);
                    input_pairs.push_back(hashes[hp + 1]);
                    next_indices.push_back(a >> 1);
                    hp += 2; k += 2;
                } else {
                    std::printf("    idx=%zu: 兄弟 %zu 从 hints[%zu] 获取\n",
                        a, sibling_idx, hint_cursor);
                    if ((a & 1) == 0) {
                        std::printf("      left = hash(idx=%zu), right = hints[%zu]\n",
                            a, hint_cursor);
                        input_pairs.push_back(hashes[hp]);
                        input_pairs.push_back(hints[hint_cursor]);
                    } else {
                        std::printf("      left = hints[%zu], right = hash(idx=%zu)\n",
                            hint_cursor, a);
                        input_pairs.push_back(hints[hint_cursor]);
                        input_pairs.push_back(hashes[hp]);
                    }
                    hint_cursor++;
                    next_indices.push_back(a >> 1);
                    hp += 1; k += 1;
                }
            }

            // 哈希所有 (left,right) 对 → 父节点
            hashes.resize(next_indices.size());
            ::whir::hash::Sha2 hh;
            hh.hash_many(64,
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t*>(input_pairs.data()),
                    input_pairs.size() * sizeof(::whir::hash::Hash)},
                std::span<::whir::hash::Hash>{hashes.data(), hashes.size()});

            std::printf("    哈希后得到 %zu 个父节点:\n", hashes.size());
            for (std::size_t i = 0; i < hashes.size(); ++i) {
                std::printf("      父节点[%zu] (索引 %zu) = ", i, next_indices[i]);
                for (std::size_t b = 0; b < 8; ++b) std::printf("%02x", static_cast<unsigned>(hashes[i][b]));
                std::printf("...\n");
            }

            idx = std::move(next_indices);
            depth++;
        }

        // 最终检查
        bool root_match = (hashes.size() == 1 && hashes[0] == root);
        bool hints_consumed = (hint_cursor == hints.size());

        std::printf("\n  最终结果:\n");
        std::printf("    重建的 root: ");
        if (hashes.size() == 1)
            for (auto b : hashes[0]) std::printf("%02x", static_cast<unsigned>(b));
        else
            std::printf("(节点数 != 1, 失败)");
        std::printf("\n");
        std::printf("    承诺的 root: ");
        for (auto b : root) std::printf("%02x", static_cast<unsigned>(b));
        std::printf("\n");
        std::printf("    根匹配:   %s\n", root_match ? "YES" : "NO");
        std::printf("    hints 全部消费: %s\n", hints_consumed ? "YES" : "NO");
    }

    // --- verify() 最终调用 ---
    hr("verify() 完整调用结果");
    std::vector<const ::whir::protocols::irs_commit::Commitment<F>*> clist{&commitment};
    auto verifier_evals = config.verify(vs, clist);

    std::printf("  返回的 points:\n");
    for (std::size_t i = 0; i < verifier_evals.points.size(); ++i)
        std::printf("    points[%zu] = %20llu\n", i,
            (unsigned long long)verifier_evals.points[i].as_canonical_u64());
    std::printf("\n  返回的 matrix:\n");
    for (std::size_t r = 0; r < verifier_evals.points.size(); ++r)
        std::printf("    row[%zu] = %20llu\n", r,
            (unsigned long long)verifier_evals.matrix[r].as_canonical_u64());
    std::printf("\n  check_eof = %s\n", vs.check_eof() ? "true" : "false");

    // =========================================================================
    hr("总结: prover vs. verifier 逐项对照");
    std::printf("  挑战索引:  prover ");
    for (auto i : indices) std::printf("%zu ", i);
    std::printf("  verifier ");
    for (auto i : v_indices) std::printf("%zu ", i);
    std::printf(" → %s\n", indices == v_indices ? "一致" : "不一致");

    std::printf("  挑战点:    %s\n",
        in_domain_evals.points == verifier_evals.points ? "一致" : "不一致");
    std::printf("  子矩阵:    %s\n",
        in_domain_evals.matrix == verifier_evals.matrix ? "一致" : "不一致");
    std::printf("  proof 完整: %s\n", vs.check_eof() ? "是" : "否");

    return 0;
}
