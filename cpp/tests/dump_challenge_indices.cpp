// ===========================================================================
// dump_challenge_indices.cpp — 挑战索引生成 golden test。
//
// 运行: ./dump_challenge_indices > golden_ci_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_ci_rs.txt) golden_ci_cpp.txt
//
// 测试 indices_from_entropy(): 从确定性 entropy 字节生成挑战索引。
// 这是 WHIR 协议中 verifier 选择哪些行需要打开的核心函数。
//
// 算法:
//   - count == 0          → 返回空
//   - num_leaves == 1     → 全返回 0
//   - 否则: size_bytes = ceil(log2(num_leaves)/8)
//     entropy 切成 count 段, 每段 size_bytes 按大端解析为整数
//     然后 mod num_leaves 得到索引
//   - dedup = true: 排序 + 去重
//
// 8 组测试用例:
//   - 128-5-dedup:     128 叶, 5 挑战, 去重,  不同 entropy → 不同索引
//   - 128-5-nodedup:   128 叶, 5 挑战, 不去重   (保留重复)
//   - 8192-5-dedup:    8192 叶, 5 挑战, 去重   (更大的域)
//   - 1m-4-dedup:      1M 叶, 4 挑战,  去重    (百万级)
//   - 128-5-dups:       128 叶, 5 挑战, 去重,  有重复 entropy → 去重后更少
//   - 1leaf-3-dedup:    1 叶, 3 挑战,  去重    → 边界: 全是 0
//   - 1leaf-3-nodedup:  1 叶, 3 挑战,  不去重  → 边界: 3 个 0
//   - 0count:            8 叶, 0 挑战           → 边界: 空
//
// 对应 Rust: examples/dump_challenge_indices.rs
// ===========================================================================

#include "whir/protocols/challenge_indices.hpp"
#include <cstdint>
#include <cstdio>
#include <vector>

int main() {
    namespace ci = whir::protocols::challenge_indices;

    // 测试用例: (标签, 叶子数, 挑战数, 去重, entropy 字节)
    struct Case {
        const char* label; 
        std::size_t nl;      // num_leaves (必须是 2 的幂)
        std::size_t cnt;     // count
        bool dedup;          // 是否去重
        std::vector<std::uint8_t> ent;  // entropy 字节 (长度 = 生成个数*每个索引需要的字节数)
    };
    const std::vector<Case> cases = {
        {"128-5-dedup",     128,              5, true,
            {0x01,0x23,0x45,0x67,0x89}},
        {"128-5-nodedup",   128,              5, false,
            {0x01,0x23,0x45,0x67,0x89}},
        {"8192-5-dedup",    8192,             5, true,
            {0x01,0x23, 0x45,0x67, 0x89,0xAB, 0xCD,0xEF, 0x12,0x34}}, //2字节拼接
        {"1m-4-dedup",      std::size_t{1}<<20, 4, true,
            {0x12,0x34,0x56, 0x78,0x9A,0xBC, 0xDE,0xF0,0x11, 0x22,0x33,0x44}},
        {"128-5-dups",      128,              5, true,
            {0x20,0x40,0x20,0x60,0x40}},       // 故意放重复字节 → 去重后索引更少
        {"1leaf-3-dedup",   1,                3, true,  {}},    // 单叶 + 去重 → [0]
        {"1leaf-3-nodedup", 1,                3, false, {}},    // 单叶 + 不去重 → [0,0,0]
        {"0count",          8,                0, true,  {}},    // 零挑战 → []
    };

    std::printf("# SECTION challenge_indices\n");
    for (std::size_t ci = 0; ci < cases.size(); ++ci) {
        const auto& c = cases[ci];
        auto r = ci::indices_from_entropy(
            std::span<const std::uint8_t>{c.ent.data(), c.ent.size()},
            c.nl, c.cnt, c.dedup);
        std::printf("CASE %zu %s num_leaves=%zu count=%zu dedup=%s entropy_len=%zu\n",
            ci, c.label, c.nl, c.cnt, c.dedup ? "true" : "false", c.ent.size());
        std::printf("  indices");
        for (auto v : r) std::printf(" %zu", v);
        std::printf("\n");
    }
    return 0;
}
