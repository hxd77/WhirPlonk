#pragma once

// ============================================================================
// merkle_tree.hpp — 二叉 Merkle 树承诺层
//
// 从叶子哈希构建二叉哈希树。内部节点计算为:
//   node[i] = H(left_child || right_child)
//
// 内存布局:
//   nodes = [叶子层(2^L) | 父层(2^{L-1}) | ... | 根(1)]
//   叶子层补齐到 2 的幂次（不足补零哈希）
//
// 提供的功能:
//   layers_for_size(n)           — ceil(log2(n))，n 个叶子的树深度
//   make_config(hash_id, n)      — 单引擎多层 Merkle 配置
//   build_tree(config, leaves)   — 自底向上构建，返回完整节点数组
//   tree_root(witness)           — 提取根哈希（nodes.back()）
//   open_path(config, w, idx)    — 生成验证提示（兄弟哈希）
//   verify_path(config, ...)     — 从叶子 + 提示重建路径，验证根
//
// Transcript 感知协议层:
//   commit()                     — 构建树 + 通过 transcript 发送根
//   receive_commitment()         — 从 transcript 读取根
//   open()                       — 通过 transcript 发送兄弟提示
//   verify()                     — 从 transcript 读取提示，验证路径
//
// 安全性: 在底层哈希的碰撞抗性下具有绑定性
// 对应 Rust 文件: src/protocols/merkle_tree.rs
// ============================================================================

#include "../engines.hpp"
#include "../hash/hash_engine.hpp"
#include "../profiling.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace whir::protocols::merkle_tree {

// ---- 类型定义 ----

/// 每层配置（支持不同层使用不同哈希引擎）。
struct LayerConfig {
    ::whir::EngineId hash_id;
};

/// Merkle 树配置。
struct Config {
    std::size_t num_leaves;
    std::vector<LayerConfig> layers;  // 根到叶的顺序（与 Rust 一致）

    /// 完全二叉树的节点总数 = 2^{L+1} - 1。
    constexpr std::size_t num_nodes() const noexcept {
        return (std::size_t{1} << (layers.size() + 1)) - 1;
    }
};

/// Merkle 树见证: 从叶子到根的完整节点数组。
struct Witness {
    // nodes[0..2^L-1] = 叶子（已补齐），nodes.back() = 根
    std::vector<::whir::hash::Hash> nodes;

    std::size_t num_nodes() const noexcept { return nodes.size(); }
};

/// Merkle 树承诺: 仅包含根哈希。
struct Commitment {
    ::whir::hash::Hash root;
};

// ---- 辅助函数 ----

/// 树深度 = ceil(log2(max(n, 1)))。
inline std::size_t layers_for_size(std::size_t size) noexcept {
    if (size <= 1) return 0;
    std::size_t pow = 1, k = 0;
    while (pow < size) { pow <<= 1; ++k; }
    return k;
}

/// 创建单引擎多层配置（所有层使用同一哈希算法）。
inline Config make_config(::whir::EngineId hash_id, std::size_t num_leaves) {
    Config c;
    c.num_leaves = num_leaves;
    c.layers.assign(layers_for_size(num_leaves), LayerConfig{hash_id});
    return c;
}

// ---- build_tree: 自底向上构建 ----

/// 从叶子哈希列表构建完整的 Merkle 树。
///
/// @pre leaves.size() == config.num_leaves
/// @param engine_lookup  可调用对象: EngineId -> const HashEngine&
/// @return 包含所有树节点（叶子到根）的 Witness
///
/// 将叶子层补齐到 2^L 个零哈希，然后逐层向上哈希:
///   parent = H(left || right)（每层中相邻节点对）
template <typename EngineLookup>
Witness build_tree(
    const Config& config,
    std::vector<::whir::hash::Hash> leaves,
    EngineLookup&& engine_lookup)
{
    assert(leaves.size() == config.num_leaves && "leaves count mismatch");

    Witness w;
    w.nodes = std::move(leaves);

    // 将叶子层补齐到 2^L 个零哈希
    const std::size_t leaf_layer_size = std::size_t{1} << config.layers.size();
    w.nodes.resize(config.num_nodes(), ::whir::hash::Hash{});

    std::size_t prev_off = 0;              // 子层在 nodes[] 中的偏移
    std::size_t prev_len = leaf_layer_size; // 子层长度
    std::size_t curr_off = leaf_layer_size; // 父层偏移

    // 自底向上: 将每对子节点哈希为一个父节点。
    // config.layers 是根到叶的顺序；反向迭代（最深的层优先）。
    {
        ::whir::profile::ScopedTimer timer("cpu", config.num_leaves, "merkle_internal_hash");
        for (auto it = config.layers.rbegin(); it != config.layers.rend(); ++it) {
            const auto& layer = *it;
            const std::size_t curr_len = prev_len / 2;
            const auto& engine = engine_lookup(layer.hash_id);

            // 将子层视为平坦字节跨度；每对 32B 哈希组成一个 64B 输入块，
            // 哈希后得到一个 32B 父节点。
            std::span<const std::uint8_t> input{
                reinterpret_cast<const std::uint8_t*>(w.nodes.data() + prev_off),
                prev_len * sizeof(::whir::hash::Hash)};

            std::span<::whir::hash::Hash> output{w.nodes.data() + curr_off, curr_len};
            engine.hash_many(64, input, output);

            prev_off = curr_off;
            prev_len = curr_len;
            curr_off += curr_len;
        }
    }
    return w;
}

/// 提取根哈希（节点数组的最后一个元素）。
inline ::whir::hash::Hash tree_root(const Witness& w) {
    assert(!w.nodes.empty());
    return w.nodes.back();
}

// ---- open_path: 生成验证提示 ----

/// 为给定叶子索引生成 Merkle 打开提示（兄弟哈希）。
///
/// 索引会被排序和去重。对于每层自底向上，如果两个兄弟都在已知集合中，
/// 则无需提示即可重建父节点；否则将缺失的兄弟哈希追加到输出。
///
/// @pre witness.nodes.size() == config.num_nodes()
/// @pre 所有索引 < config.num_leaves
/// @return 验证所需的兄弟哈希向量
inline std::vector<::whir::hash::Hash> open_path(
    const Config& config,
    const Witness& witness,
    std::span<const std::size_t> raw_indices)
{
    assert(witness.nodes.size() == config.num_nodes());
    for (auto i : raw_indices) {
        (void)i;
        assert(i < config.num_leaves);
    }

    // 排序 + 去重索引
    std::vector<std::size_t> indices(raw_indices.begin(), raw_indices.end());
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());

    std::vector<::whir::hash::Hash> hints;

    std::size_t layer_off = 0;
    std::size_t layer_len = std::size_t{1} << config.layers.size();

    // 自底向上: 每层中，为未配对的节点输出兄弟哈希。
    while (layer_len > 1) {
        std::vector<std::size_t> next_indices;
        next_indices.reserve(indices.size());

        for (std::size_t k = 0; k < indices.size();) {
            const std::size_t a = indices[k];
            // a^1 翻转最低位: 0<->1, 2<->3 等（兄弟索引）
            const bool merge = (k + 1 < indices.size()) && (indices[k + 1] == (a ^ 1));
            if (merge) {
                // 两个兄弟都存在 -> 验证者可以重建父节点
                next_indices.push_back(a >> 1);
                k += 2;
            } else {
                // 兄弟缺失 -> 输出其哈希作为提示
                hints.push_back(witness.nodes[layer_off + (a ^ 1)]);
                next_indices.push_back(a >> 1);
                k += 1;
            }
        }
        indices = std::move(next_indices);
        layer_off += layer_len;
        layer_len /= 2;
    }
    return hints;
}

// ---- verify_path: 从叶子 + 提示重建根 ----

/// 验证 Merkle 打开: 从叶子哈希和提示重建根，然后与声明的根比较。
///
/// @param leaf_hashes  必须与 @p indices 一一对应（允许重复但哈希必须相同）
/// @param hints        来自 open_path() 的兄弟哈希
/// @return 当且仅当重建的根匹配 @p root 时返回 true
template <typename EngineLookup>
bool verify_path(
    const Config& config,
    const ::whir::hash::Hash& root,
    std::span<const std::size_t> indices,
    std::span<const ::whir::hash::Hash> leaf_hashes,
    std::span<const ::whir::hash::Hash> hints,
    EngineLookup&& engine_lookup)
{
    if (indices.size() != leaf_hashes.size()) return false;
    for (auto i : indices) if (i >= config.num_leaves) return false;
    if (indices.empty()) return true;

    // 配对 (index, hash)，按索引排序，检查重复一致性
    std::vector<std::pair<std::size_t, ::whir::hash::Hash>> layer;
    layer.reserve(indices.size());
    for (std::size_t k = 0; k < indices.size(); ++k) {
        layer.emplace_back(indices[k], leaf_hashes[k]);
    }
    std::sort(layer.begin(), layer.end(),
        [](const auto& l, const auto& r) { return l.first < r.first; });

    // 重复索引但哈希不同 -> 拒绝
    for (std::size_t k = 1; k < layer.size(); ++k) {
        if (layer[k - 1].first == layer[k].first &&
            layer[k - 1].second != layer[k].second) {
            return false;
        }
    }

    // 按索引去重（保留首次出现）
    layer.erase(std::unique(layer.begin(), layer.end(),
        [](const auto& l, const auto& r) { return l.first == r.first; }), layer.end());

    // 拆分为并行的索引和哈希数组
    std::vector<std::size_t> idx;
    std::vector<::whir::hash::Hash> hashes;
    idx.reserve(layer.size());
    hashes.reserve(layer.size());
    for (auto& [i, h] : layer) {
        idx.push_back(i);
        hashes.push_back(h);
    }

    // 自底向上重建: 每层中，将已知节点与兄弟配对（两个都已知或一个来自提示），
    // 哈希配对得到父节点。
    std::size_t hint_cursor = 0;
    for (auto it = config.layers.rbegin(); it != config.layers.rend(); ++it) {
        const auto& layer_cfg = *it;

        std::vector<std::size_t> next_indices;
        std::vector<::whir::hash::Hash> input_pairs;
        input_pairs.reserve(idx.size() * 2);

        std::size_t hp = 0;  // hashes[] 的游标

        for (std::size_t k = 0; k < idx.size();) {
            const std::size_t a = idx[k];
            const bool merge = (k + 1 < idx.size()) && (idx[k + 1] == (a ^ 1));
            if (merge) {
                // 两个兄弟都已知
                input_pairs.push_back(hashes[hp + 0]);
                input_pairs.push_back(hashes[hp + 1]);
                next_indices.push_back(a >> 1);
                hp += 2;
                k += 2;
            } else {
                // 从提示中取出兄弟；按奇偶性确定左右顺序
                if (hint_cursor >= hints.size()) return false;
                const auto& h = hints[hint_cursor++];
                if ((a & 1) == 0) {  // a 为偶数 -> 左子节点
                    input_pairs.push_back(hashes[hp]);
                    input_pairs.push_back(h);
                } else {              // a 为奇数 -> 右子节点
                    input_pairs.push_back(h);
                    input_pairs.push_back(hashes[hp]);
                }
                next_indices.push_back(a >> 1);
                hp += 1;
                k += 1;
            }
        }

        // 哈希所有 (left, right) 对以产生父层节点
        hashes.resize(next_indices.size());
        const auto& engine = engine_lookup(layer_cfg.hash_id);
        engine.hash_many(64,
            std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t*>(input_pairs.data()),
                input_pairs.size() * sizeof(::whir::hash::Hash)},
            std::span<::whir::hash::Hash>{hashes.data(), hashes.size()});

        idx = std::move(next_indices);
    }

    // 最终检查: 恰好剩余一个节点，所有提示已消费，根匹配
    return hashes.size() == 1 && hint_cursor == hints.size() && hashes[0] == root;
}

// ============================================================================
// Transcript 感知的 Merkle 树协议
// ============================================================================

/// 构建树并通过 transcript 发送根哈希作为承诺。
///
/// 对应 Rust: merkle_tree::commit()
///   1. build_tree(config, leaves, engine_lookup) -> Witness
///   2. prover_message(tree_root(witness))        -> 发送根
template <typename Transcript, typename EngineLookup>
Witness commit(
    Transcript& prover_state,
    const Config& config,
    std::vector<::whir::hash::Hash> leaves,
    EngineLookup&& engine_lookup)
{
    Witness w = build_tree(config, std::move(leaves), std::forward<EngineLookup>(engine_lookup));
    prover_state.prover_message(w.nodes.back());
    return w;
}

/// 从 transcript 接收根哈希 -> Commitment。
///
/// 对应 Rust: merkle_tree::receive_commitment()
template <typename Transcript>
Commitment receive_commitment(Transcript& verifier_state) {
    Commitment c;
    verifier_state.prover_message(c.root);
    return c;
}

/// 通过 transcript 为给定叶子索引发送兄弟提示。
///
/// 对应 Rust: merkle_tree::open()
///   每个提示序列化为原始 32B Hash（无长度前缀）。
template <typename Transcript>
void open(
    Transcript& prover_state,
    const Config& config,
    const Witness& witness,
    std::span<const std::size_t> indices)
{
    auto hints = open_path(config, witness, indices);
    for (auto& h : hints)
        prover_state.prover_hint(h);
}

/// 从 transcript 提示（内联）重建 Merkle 路径并验证根。
///
/// 按需从 transcript 读取提示，与证明者的逐个 prover_hint() 调用匹配。
/// 这避免了在验证者端物化完整的提示数组。
template <typename Transcript, typename EngineLookup>
bool verify_path_from_transcript(
    Transcript& verifier_state,
    const Config& config,
    const ::whir::hash::Hash& root,
    std::span<const std::size_t> indices,
    std::span<const ::whir::hash::Hash> leaf_hashes,
    EngineLookup&& engine_lookup)
{
    if (indices.size() != leaf_hashes.size()) return false;
    for (auto i : indices) if (i >= config.num_leaves) return false;
    if (indices.empty()) return true;

    // 配对 (index, hash)，排序，检查重复一致性，去重
    std::vector<std::pair<std::size_t, ::whir::hash::Hash>> layer;
    layer.reserve(indices.size());
    for (std::size_t k = 0; k < indices.size(); ++k)
        layer.emplace_back(indices[k], leaf_hashes[k]);
    std::sort(layer.begin(), layer.end(),
        [](const auto& l, const auto& r) { return l.first < r.first; });

    for (std::size_t k = 1; k < layer.size(); ++k)
        if (layer[k - 1].first == layer[k].first &&
            layer[k - 1].second != layer[k].second)
            return false;

    layer.erase(std::unique(layer.begin(), layer.end(),
        [](const auto& l, const auto& r) { return l.first == r.first; }), layer.end());

    std::vector<std::size_t> idx;
    std::vector<::whir::hash::Hash> hashes;
    idx.reserve(layer.size()); hashes.reserve(layer.size());
    for (auto& [i, h] : layer) { idx.push_back(i); hashes.push_back(h); }

    // 自底向上: 按需从 transcript 读取提示
    for (auto it = config.layers.rbegin(); it != config.layers.rend(); ++it) {
        const auto& layer_cfg = *it;

        std::vector<std::size_t> next_indices;
        std::vector<::whir::hash::Hash> input_pairs;
        input_pairs.reserve(idx.size() * 2);
        std::size_t hp = 0;

        for (std::size_t k = 0; k < idx.size();) {
            const std::size_t a = idx[k];
            const bool merge = (k + 1 < idx.size()) && (idx[k + 1] == (a ^ 1));
            if (merge) {
                input_pairs.push_back(hashes[hp + 0]);
                input_pairs.push_back(hashes[hp + 1]);
                next_indices.push_back(a >> 1);
                hp += 2; k += 2;
            } else {
                // 从 transcript 读取一个提示（Rust: verifier_state.prover_hint()）
                ::whir::hash::Hash h;
                if (!verifier_state.prover_hint(h)) return false;
                if ((a & 1) == 0) {
                    input_pairs.push_back(hashes[hp]);
                    input_pairs.push_back(h);
                } else {
                    input_pairs.push_back(h);
                    input_pairs.push_back(hashes[hp]);
                }
                next_indices.push_back(a >> 1);
                hp += 1; k += 1;
            }
        }

        hashes.resize(next_indices.size());
        const auto& engine = engine_lookup(layer_cfg.hash_id);
        engine.hash_many(64,
            std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t*>(input_pairs.data()),
                input_pairs.size() * sizeof(::whir::hash::Hash)},
            std::span<::whir::hash::Hash>{hashes.data(), hashes.size()});
        idx = std::move(next_indices);
    }

    return hashes.size() == 1 && hashes[0] == root;
}

/// 根据承诺验证 Merkle 打开，从 transcript 读取提示。
///
/// 对应 Rust: merkle_tree::verify()
template <typename Transcript, typename EngineLookup>
bool verify(
    Transcript& verifier_state,
    const Config& config,
    const Commitment& commitment,
    std::span<const std::size_t> indices,
    std::span<const ::whir::hash::Hash> leaf_hashes,
    EngineLookup&& engine_lookup)
{
    return verify_path_from_transcript(verifier_state, config, commitment.root,
        indices, leaf_hashes, std::forward<EngineLookup>(engine_lookup));
}

} // namespace whir::protocols::merkle_tree
