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

    //lambda匿名函数
    // 引擎查找函数: 根据 EngineId 返回对应的引擎引用
    auto el = [&](whir::EngineId id) -> const whir::hash::HashEngine& { //输入一个引擎ID,用于指定需要哪种哈希，输出一个对应的哈希对象
        if (id == whir::hash::ENGINE_ID_BLAKE3) return b3e;
        if (id == whir::hash::ENGINE_ID_SHA2) return s2e;
        std::abort();
    };

    // 测试用例: (标签, 引擎ID, 叶子数, 打开的索引列表)
    struct Case { const char* label; //测试用例的名称标签
                  whir::EngineId hid; //哈希引擎ID
                  std::size_t nl;     //叶子个数
                  std::vector<std::size_t> idx; //索引列表
                }; 
    const std::vector<Case> cases = {
        //用例1:BLAKE3,16个节点,索引[3,5,11]
        {"blake3-16-2", whir::hash::ENGINE_ID_BLAKE3, 16, {3, 5, 11}},
        {"blake3-32-3", whir::hash::ENGINE_ID_BLAKE3, 32, {0, 1, 2, 31}},
        {"sha2-8-2",    whir::hash::ENGINE_ID_SHA2,    8, {2, 6}},
    };

    std::printf("# SECTION merkle_tree\n");
    for (std::size_t ci = 0; ci < cases.size(); ++ci) {
        const auto& c = cases[ci];

        // 生成确定性叶子: leaf[i][j] = (i*31 + j) & 0xFF
        std::vector<Hash> leaves(c.nl);
        for (std::size_t i = 0; i < c.nl; ++i) //外层:遍历每个叶子
            for (std::size_t j = 0; j < 32; ++j) //内层: 填充32字节
                leaves[i][j] = (uint8_t)((i * 31 + j) & 0xFF); //构造哈希

        // 构建 Merkle 树
        auto cfg = mt::make_config(c.hid, c.nl);     // 按叶子数+引擎生成配置
        auto w = mt::build_tree(cfg, leaves, el);     // 自底向上构建
        auto layers = mt::layers_for_size(c.nl);       // 树层数 = ceil(log2(nl))
        auto leaf_layer = std::size_t{1} << layers;   // 补齐后的叶子层大小
        auto root = mt::tree_root(w);                  // 根节点 (nodes.back())
        auto hints = mt::open_path(cfg, w,
            std::span<const std::size_t>{c.idx.data(), c.idx.size()}); // 生成打开路径 

        std::printf("CASE %zu %s num_leaves=%zu\n", ci, c.label, c.nl);
        dump_hash("root", root);
        std::printf("  leaf_layer %zu\n  num_hints %zu\n", leaf_layer, hints.size());
        for (std::size_t i = 0; i < hints.size(); ++i) {
            char b[16]; //1.char b[16]声明字符数组 
            std::snprintf(b, 16, "hint%zu", i); //2.b:目标缓冲区,16:缓冲区最大大小 ,%zu是std::size_t类型的格式说明符
            dump_hash(b, hints[i]);
        }
    }
    return 0;
}
