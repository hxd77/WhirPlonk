// ===========================================================================
// dump_merkle_tree.cpp — Merkle 树 golden test。
//
// 运行: ./dump_merkle_tree > golden_merkle_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_merkle_rs.txt) golden_merkle_cpp.txt
//
// 测试 Merkle 树的构建 + 打开路径:
//   1. build_tree: 自底向上, 每对相邻叶子 (64 字节) 哈希成父节点 (32 字节)
//   2. open_path:  给定叶子索引, 返回验证所需的 sibling hash 列表
//
// 3 组测试用例:
//   - BLAKE3 引擎, 16 叶子, 打开索引 [3, 5, 11]
//   - BLAKE3 引擎, 32 叶子, 打开索引 [0, 1, 2, 31]  (边界索引)
//   - SHA2   引擎,  8 叶子, 打开索引 [2, 6]
//
// 叶子生成规则 (与 Rust 完全一致):
//   leaf[i][j] = (i * 31 + j) & 0xFF
//
// 对应 Rust: examples/dump_merkle_tree.rs
// ===========================================================================

#include "whir/hash/blake3_engine.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

int main() {
    // 打印哈希为 64 字符十六进制字符串
    auto dump_hash = [](const char* label, const whir::hash::Hash& h) {
        std::printf("  %s ", label);
        for (auto byte : h) std::printf("%02x", static_cast<unsigned>(byte));
        std::printf("\n");
    };

    namespace mt = whir::protocols::merkle_tree;
    using whir::hash::Hash;

    // 引擎实例
    whir::hash::Blake3 b3e;
    whir::hash::Sha2 s2e;

    // 引擎查找函数: 根据 EngineId 返回对应的引擎引用
    auto el = [&](whir::EngineId id) -> const whir::hash::HashEngine& {
        if (id == whir::hash::ENGINE_ID_BLAKE3) return b3e;
        if (id == whir::hash::ENGINE_ID_SHA2) return s2e;
        std::abort();
    };

    // 测试用例: (标签, 引擎ID, 叶子数, 打开的索引列表)
    struct Case { const char* label;
                  whir::EngineId hid;
                  std::size_t nl;
                  std::vector<std::size_t> idx;
                };
    const std::vector<Case> cases = {
        {"blake3-16-2", whir::hash::ENGINE_ID_BLAKE3, 16, {3, 5, 11}},
        {"blake3-32-3", whir::hash::ENGINE_ID_BLAKE3, 32, {0, 1, 2, 31}},
        {"sha2-8-2",    whir::hash::ENGINE_ID_SHA2,    8, {2, 6}},
    };

    std::printf("# SECTION merkle_tree\n");
    for (std::size_t ci = 0; ci < cases.size(); ++ci) {
        const auto& c = cases[ci];

        // 生成确定性叶子: leaf[i][j] = (i*31 + j) & 0xFF
        std::vector<Hash> leaves(c.nl);
        for (std::size_t i = 0; i < c.nl; ++i)
            for (std::size_t j = 0; j < 32; ++j)
                leaves[i][j] = (uint8_t)((i * 31 + j) & 0xFF);

        // 构建 Merkle 树
        auto cfg = mt::make_config(c.hid, c.nl);
        auto w = mt::build_tree(cfg, leaves, el);
        auto layers = mt::layers_for_size(c.nl);
        auto leaf_layer = std::size_t{1} << layers;
        auto root = mt::tree_root(w);
        auto hints = mt::open_path(cfg, w,
            std::span<const std::size_t>{c.idx.data(), c.idx.size()});

        std::printf("CASE %zu %s num_leaves=%zu\n", ci, c.label, c.nl);
        dump_hash("root", root);
        std::printf("  leaf_layer %zu\n  num_hints %zu\n", leaf_layer, hints.size());
        for (std::size_t i = 0; i < hints.size(); ++i) {
            char b[16];
            std::snprintf(b, 16, "hint%zu", i);
            dump_hash(b, hints[i]);
        }
    }
    return 0;
}
