#pragma once

// ===========================================================================
// merkle_tree.hpp — Merkle 树纯函数层
// 对应 WHIR 中的 src/protocols/merkle_tree.rs。
//
// 用哈希引擎构建二叉树承诺: 叶子 → 父节点 = H(left_child || right_child)
//
// WHIR 中的用途:
//   IRS commit 对编码矩阵的每一行做哈希得到叶子, 再构建 Merkle 树承诺。
//   verifier 随机挑选几个叶子要求打开, prover 提供 Merkle 路径 (sibling hints)。
//
// 提供的函数:
//   layers_for_size(n)               — ceil(log2(n)), n 个叶子需要多少层
//   make_config(hash_id, n)          — 创建单引擎多层的 Merkle 配置
//   build_tree(config, leaves, el)   — 自底向上构建, 返回完整节点数组
//   tree_root(witness)               — 提取根哈希 (nodes.back())
//   open_path(config, w, indices)    — 生成 verification hints
//   verify_path(config, r, idx, l, h, el) — 从叶子和 hints 重建路径, 验证 root
//
// 内存布局:
//   nodes = [叶子层(2^L) | 父层1(2^{L-1}) | 父层2(2^{L-2}) | ... | root(1)]
//   叶子层补齐到 2 的幂次 (不足补零 Hash)
//   自底向上, 每对相邻节点 (64B = 32B+32B) 哈希成 32B 父节点
//
// 对应 Rust: protocols/merkle_tree.rs
// ===========================================================================

#include "../engines.hpp"
#include "../hash/hash_engine.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace whir::protocols::merkle_tree {

// ---- 类型定义 ----

/// 每层的配置 (支持不同层用不同哈希引擎)
struct LayerConfig {
    ::whir::EngineId hash_id;
};

/// Merkle 树配置
struct Config {
    std::size_t num_leaves;              // 叶子数量
    std::vector<LayerConfig> layers;     // 从 root 到底的描述 (与 Rust 一致)

    /// 完全二叉树的总节点数 = 2^{L+1} - 1
    constexpr std::size_t num_nodes() const noexcept {
        return (std::size_t{1} << (layers.size() + 1)) - 1; //L是层数
    }
};

/// Merkle 树见证 = 全部节点 (从叶子到根)
struct Witness {
    // 从叶子层开始向上。nodes[0..2^L-1] = 叶子 (补齐), nodes.back() = root
    std::vector<::whir::hash::Hash> nodes;

    std::size_t num_nodes() const noexcept { return nodes.size(); }
};

/// Merkle 树承诺 = 根哈希
struct Commitment {
    ::whir::hash::Hash root;
};

// ---- 辅助函数 ----

//求以2为底的对数的向上取整
/// 计算 n 个叶子需要的树层数 = ceil(log2(max(n, 1)))
inline std::size_t layers_for_size(std::size_t size) noexcept { //size:元素数量
    if (size <= 1) return 0;
    std::size_t pow = 1, k = 0; //pow代表当前能容纳的节点容量,初始为2^0=1,k代表当前层数初始为0
    while (pow < size) { pow <<= 1; ++k; }
    return k;
}

/// 创建单引擎多层 Merkle 配置 (所有层用相同 hash_id)
inline Config make_config(::whir::EngineId hash_id, std::size_t num_leaves) {//EngineId表示指定哪种哈希算法，num_leaves:叶子节点数量，表示要哈希的原始数据块个数
    Config c;
    c.num_leaves = num_leaves; //底层大小
    c.layers.assign(layers_for_size(num_leaves), LayerConfig{hash_id}); //算层数,并表示这一层的哈希计算用hash_id算法
    //assign表示把这个数组调整为这么长,并且里面每一个元素都设成这个值
    return c;
}

// ---- build_tree: 自底向上构建 ----

/// 从叶子列表构建完整 Merkle 树。
/// leaves 长度必须 == config.num_leaves。
/// engine_lookup(EngineId) 返回对应的哈希引擎引用。
template <typename EngineLookup>
Witness build_tree(
    const Config& config,
    std::vector<::whir::hash::Hash> leaves, //底层经过哈希处理的叶子节点 
    EngineLookup&& engine_lookup)  //&&表示万能引用，传进去一个lambda匿名函数,比如[](whir::Engine::hash_id){return blak3();}
{
    assert(leaves.size() == config.num_leaves && "leaves count mismatch");

    Witness w;
    w.nodes = std::move(leaves);

    // 叶子层补齐到 2^L, 不足的用零 Hash 填充
    const std::size_t leaf_layer_size = std::size_t{1} << config.layers.size(); //Merkle树的底层大小,即leaf_layer_size必须是2^n,假设leaf_layer_size=4
    w.nodes.resize(config.num_nodes(), ::whir::hash::Hash{}); //数组长度为num_nodes,多出来的数据用全零hash填充,那么num_nodes=2^3-1=7

    std::size_t prev_off = 0;             // 上一层在 nodes 中的起始偏移
    std::size_t prev_len = leaf_layer_size; // 上一层长度
    std::size_t curr_off = leaf_layer_size; // 当前层起始偏移

    // 从叶子上一层层往上哈希到根
    // config.layers 从根到叶 (Rust 端 iter().rev() 从最深层开始)
    for (auto it = config.layers.rbegin(); it != config.layers.rend(); ++it) { //逆序(从叶子层往根节点向上)
        const auto& layer = *it;
        const std::size_t curr_len = prev_len / 2;  // 每层长度减半,向上找父节点
        const auto& engine = engine_lookup(layer.hash_id); //找到这层使用的hash算法

        // 两个相邻 32B Hash = 64B 输入, 哈希成 32B 输出
        //input是一个只读span,存了所有内存子节点字节数据,span是一个轻量级、不拥有数据的"连续内存视图"
        std::span<const std::uint8_t> input{
            //w.nodes.data()是w.nodes在内存里的首地址,加上prev_off上一层的偏移量到要处理的子节点层
            reinterpret_cast<const std::uint8_t*>(w.nodes.data() + prev_off), //reinterpret_cast<const std::uint8_t*>表示别管原来是什么，现在看成一长串单字节指针(uint8_t*)
            prev_len * sizeof(::whir::hash::Hash)}; //prev_len*sizeof()表示这一层有多少字节(节点数*每个节点大小)

        //curr_off表示要写入的父节点层的初始位置,curr_len表示写入长度
        std::span<::whir::hash::Hash> output{w.nodes.data() + curr_off, curr_len};
        engine.hash_many(64, input, output); //一个hash是32字节,左右两个节点合并成一个父节点所以是64字节

        prev_off = curr_off;
        prev_len = curr_len;
        curr_off += curr_len;
    }
    return w;
}

/// 提取根哈希 (nodes 数组的最后一个元素)
inline ::whir::hash::Hash tree_root(const Witness& w) {
    assert(!w.nodes.empty());
    return w.nodes.back(); //最后一个元素,root
}

// ---- open_path: 生成验证路径 ----

/// 对给定的叶子索引生成 Merkle 打开路径 (sibling hints)。
/// 路径按 Rust 端顺序: 索引先排序去重, 然后自底向上收集所需的 sibling。
/// 返回的 hints 顺序和 Rust 端一致。
inline std::vector<::whir::hash::Hash> open_path(
    const Config& config, //配置
    const Witness& witness, //树
    std::span<const std::size_t> raw_indices) //用户想要查询的叶子节点索引列表
{ //返回一组哈希值数组
    assert(witness.nodes.size() == config.num_nodes());
    for (auto i : raw_indices) {
        (void)i; //抑制未使用变量的警告
        assert(i < config.num_leaves);
    }

    // 排序 + 去重
    std::vector<std::size_t> indices(raw_indices.begin(), raw_indices.end()); //用indices存储
    std::sort(indices.begin(), indices.end()); //排序
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());//去重

    std::vector<::whir::hash::Hash> hints;

    std::size_t layer_off = 0; //层偏移量
    std::size_t layer_len = std::size_t{1} << config.layers.size();  //当前层的节点数量

    // 自底向上: 每一层, 对于每个 index, 如果其 sibling 不在集合中就加入 hint
    while (layer_len > 1) {
        std::vector<std::size_t> next_indices; //下一层要处理的父节点
        next_indices.reserve(indices.size());

        for (std::size_t k = 0; k < indices.size();) {
            const std::size_t a = indices[k];  //当前要处理的节点索引
            // a^1 = a 的 sibling (最低位翻转: 0↔1, 2↔3, ...),二进制里，只要^1,就会算出兄弟节点索引
            const bool merge = (k + 1 < indices.size()) && (indices[k + 1] == (a ^ 1)); //下一个索引存在吗,下一个索引正好是当前节点的兄弟吗
            if (merge) {
                // sibling 也在集合中 → 两个都已知, 可以在验证时重建父节点
                next_indices.push_back(a >> 1);  // 父节点索引=a/2
                k += 2;//如果要找的两个节点都在indices中,则跳过两个如indices=[0,1,5,7], 一开始indices[0]=0,然后1也在indices里,所以k+=2=2,到查询indices[2]=5
            } else {
                // sibling 不在集合indices中 → 需要加入 hint
                hints.push_back(witness.nodes[layer_off + (a ^ 1)]);// 添加兄弟节点哈希 查询indices[2]=5,5^1=4不在indices中,hints=[hash(节点4)]
                next_indices.push_back(a >> 1);
                k += 1;//只跳过一个节点,k+=1=3,查询indices[3]=7
            }
        }
        indices = std::move(next_indices); 
        layer_off += layer_len; //层偏移量加上当前层节点数
        layer_len /= 2; //当前层数/2进入下一层父节点
    }
    return hints;
}

// ---- verify_path: 从叶子 + hints 重建根, 验证 ----

/// 用叶子和 hints 自底向上重建路径, 与声称的 root 比对。
/// leaf_hashes 与 indices 一一对应 (允许重复; 重复索引必须给相同 hash)。
template <typename EngineLookup>
bool verify_path(
    const Config& config,
    const ::whir::hash::Hash& root,
    std::span<const std::size_t> indices,//要求的索引节点,已知
    std::span<const ::whir::hash::Hash> leaf_hashes,
    std::span<const ::whir::hash::Hash> hints,//要提供的
    EngineLookup&& engine_lookup)
{
    if (indices.size() != leaf_hashes.size()) return false; //索引数量必须等于哈希数量
    for (auto i : indices) if (i >= config.num_leaves) return false; //所有索引必须在有效范围内
    if (indices.empty()) return true;  // 空证明 — 无条件接受

    // 合并 (index, hash), 排序, 检查重复一致性, 去重
    //将索引和对应的哈希值配对,pair把两个对象绑定在一起 std::pair<类型1,类型2> 变量名;
    //假设输入：indices=[5, 1, 3], leaf_hashes=[H5, H1, H3]
    //输出layer=[(5,H5), (1,H1), (3,H3)]
    std::vector<std::pair<std::size_t, ::whir::hash::Hash>> layer;
    layer.reserve(indices.size());
    for (std::size_t k = 0; k < indices.size(); ++k) {
        layer.emplace_back(indices[k], leaf_hashes[k]); //emplace_back表示直接在容器中构造,不像push_back那样先构造再移动
    }

    //按索引升序排序
    std::sort(layer.begin(), layer.end(),
        [](const auto& l, const auto& r) { return l.first < r.first; });

    // 检查重复索引的 hash 一致 (否则作弊)
    //例如indices = [3, 5, 3]
    //leaf_hashes = [H3_fake, H5, H3_real]
    //排序后：[(3, H3_fake), (3, H3_real), (5, H5)]
    //检测到：索引 3 出现两次，但哈希值不同 → 返回 false
    for (std::size_t k = 1; k < layer.size(); ++k) {
        if (layer[k - 1].first == layer[k].first &&
            layer[k - 1].second != layer[k].second) {
            return false;
        }
    }

    //去重,保留第一个出现的
    layer.erase(std::unique(layer.begin(), layer.end(), //unique把不重复元素放到数组前面,重复元素放到数组后面。比较器:比较first(索引)
        [](const auto& l, const auto& r) { return l.first == r.first; }), layer.end());  //erase(新尾巴指针,layer.end())删除从新尾巴指针开始后半段不要的

    // 准备自底向上重建
    //将layer中的pair拆分成两个独立数组
    //例子：
    // 输入: layer = [(1, H1), (3, H3), (5, H5)]
    // 输出:
    //idx    = [1, 3, 5]
    //hashes = [H1, H3, H5]
    std::vector<std::size_t> idx;
    std::vector<::whir::hash::Hash> hashes;
    idx.reserve(layer.size());
    hashes.reserve(layer.size());
    for (auto& [i, h] : layer) {
        idx.push_back(i);
        hashes.push_back(h);
    }

    //逐层向上处理
    std::size_t hint_cursor = 0; //hint的读取位置
    for (auto it = config.layers.rbegin(); it != config.layers.rend(); ++it) { //反向遍历
        const auto& layer_cfg = *it;

        
        std::vector<std::size_t> next_indices;//下一层的节点索引
        std::vector<::whir::hash::Hash> input_pairs;  // 每对为一个 [left, right]用于哈希输入
        input_pairs.reserve(idx.size() * 2);

        std::size_t hp = 0;  // 当前层已知节点的游标 hashes的读取位置

        for (std::size_t k = 0; k < idx.size();) { //循环处理每个节点
            const std::size_t a = idx[k];
            const bool merge = (k + 1 < idx.size()) && (idx[k + 1] == (a ^ 1)); 
            if (merge) {
                // 两个 sibling 都在已知集合中
                input_pairs.push_back(hashes[hp + 0]); //左子节点
                input_pairs.push_back(hashes[hp + 1]); //右子节点
                next_indices.push_back(a >> 1); //父节点索引
                hp += 2; //消耗了2个hash值
                k += 2; //跳过两个索引
            } else {
                // 需要从 hints 中取 sibling
                if (hint_cursor >= hints.size()) return false; //hints不够->验证失败
                const auto& h = hints[hint_cursor++];
                // 按正确顺序排列 left/right (偶数 index 的 sibling 在右边)
                if ((a & 1) == 0) { //a是偶数->左子节点
                    input_pairs.push_back(hashes[hp]); //左=已知
                    input_pairs.push_back(h); //右=hint
                } else { //a是奇树->右子节点
                    input_pairs.push_back(h); //左=hint
                    input_pairs.push_back(hashes[hp]); //右=已知
                }
                next_indices.push_back(a >> 1);
                hp += 1; //只消耗1个哈希值
                k += 1; //跳过1个索引
            }
        }

        // 对本层所有 (left, right) 对做哈希, 得到上一层节点
        //一次性计算所有父节点哈希
        //输入：input_pairs = [H0, H1, H4, H5, ...]
        //输出：hashes = [hash(H0||H1), hash(H4||H5), ...]=[HN1,HN2]
        hashes.resize(next_indices.size()); 
        const auto& engine = engine_lookup(layer_cfg.hash_id);
        engine.hash_many(64,
            std::span<const std::uint8_t>{
                //input_pairs.data()的类型是Hash*->uint8_t*,input_pairs.size()*sizeof(::whir::hash::Hash)字节大小  
                reinterpret_cast<const std::uint8_t*>(input_pairs.data()), //输入的H0和H1都是32字节，输出64字节到hashes中
                input_pairs.size() * sizeof(::whir::hash::Hash)},
            std::span<::whir::hash::Hash>{hashes.data(), hashes.size()}); 


        //准备下一层:将父节点索引作为下一层输入继续往上
        idx = std::move(next_indices);
    }

    // 最终应该只剩一个节点 — 根
    return hashes.size() == 1 && hint_cursor == hints.size() && hashes[0] == root;
}

// =============================================================================
// Transcript 感知的 Merkle 树协议 (对标 Rust merkle_tree.rs)
// =============================================================================

// 引用 Rust merkle_tree::commit():
//   1. build_tree(config, leaves, engine_lookup) → Witness
//   2. prover_message(tree_root(witness))        → 发送 root 承诺
//   3. return Witness (包含全部节点, 用于后续 open)
template <typename Transcript, typename EngineLookup>
Witness commit(
    Transcript& prover_state, //prover状态
    const Config& config, //配置
    std::vector<::whir::hash::Hash> leaves, //叶子
    EngineLookup&& engine_lookup)
{
    // 1. 构建 Merkle 树 ,w是Merkle Tree见证
    Witness w = build_tree(config, std::move(leaves), std::forward<EngineLookup>(engine_lookup));//forward表示保留所有地将这个参数向下传递给更底层的函数
    // 2. 发送根哈希作为承诺
    prover_state.prover_message(w.nodes.back()); //把root吸入海绵,同时序列化后追加到proof
    return w; //返回Merkle Tree见证
}

// 引用 Rust merkle_tree::receive_commitment():
//   从 transcript 读取根哈希 → Commitment
template <typename Transcript>
Commitment receive_commitment(Transcript& verifier_state) {
    Commitment c; //root哈希
    verifier_state.prover_message(c.root); //verifier将root吸入海绵
    return c; //返回root
}

// 引用 Rust merkle_tree::open():
//   对每个需要的叶子索引, 逐个发送 sibling hint (匹配 Rust 逐个 prover_hint 调用)。
//   Rust 端在循环内逐次调用 prover_state.prover_hint(&layer[a ^ 1]),
//   每个 hint 序列化为 32 字节裸 Hash, 无长度前缀。
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

// verify_path_from_transcript: 对标 Rust merkle_tree::verify()
//   在重建 Merkle 路径的过程中按需从 transcript 读取 hint,
//   与 prover 的逐个 prover_hint 调用一一对应。
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

    // 合并 (index, hash), 排序, 去重
    std::vector<std::pair<std::size_t, ::whir::hash::Hash>> layer;
    layer.reserve(indices.size());
    for (std::size_t k = 0; k < indices.size(); ++k)
        layer.emplace_back(indices[k], leaf_hashes[k]);
    std::sort(layer.begin(), layer.end(),
        [](const auto& l, const auto& r) { return l.first < r.first; });

    // 检查重复索引一致
    for (std::size_t k = 1; k < layer.size(); ++k)
        if (layer[k - 1].first == layer[k].first &&
            layer[k - 1].second != layer[k].second)
            return false;

    layer.erase(std::unique(layer.begin(), layer.end(),
        [](const auto& l, const auto& r) { return l.first == r.first; }), layer.end());

    // 拆分为 idx + hashes
    std::vector<std::size_t> idx;
    std::vector<::whir::hash::Hash> hashes;
    idx.reserve(layer.size()); hashes.reserve(layer.size());
    for (auto& [i, h] : layer) { idx.push_back(i); hashes.push_back(h); }

    // 逐层向上重建, 按需从 transcript 读取 hint
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
                // 从 transcript 读取一个 hint (对标 Rust: let hint = verifier_state.prover_hint()?;)
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

// 引用 Rust merkle_tree::verify():
//   对标 Rust 端, 按需从 transcript 逐个读取 hint 并验证 Merkle 路径。
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
