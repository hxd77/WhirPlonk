#pragma once

// =============================================================================
// irs_commit.hpp — Interleaved Reed-Solomon 承诺协议
// 对应 WHIR 中的 src/protocols/irs_commit.rs。
//
// 把多个向量矩阵编码为 RS 码字并承诺, 支持域内 (in-domain) 和域外 (out-of-domain)
// 打开。这是 WHIR 协议中多项式承诺的核心组件。
//
// 数据流:
//   原始向量 (num_vectors × vector_size)
//     ↓ interleaved_rs_encode (NTT RS 编码)
//   编码矩阵 (codeword_length × [num_vectors * interleaving_depth])
//     ↓ commit_leaves (逐行 LE 编码 + 哈希)
//   叶子哈希列表 (codeword_length 个 Hash)
//     ↓ merkle_tree::commit (构建 Merkle 树, transcript 发送 root)
//   Merkle 见证 (含全部节点)
//     ↓ 域外采样 (verifier_message_vec 挤出随机点)
//   域外求值 (mixed_univariate_evaluate)
//     → Witness{matrix, matrix_witness, out_of_domain}
//
// 域内打开 (open/verify):
//   1. transcript 挤出挑战索引 (challenge_indices)
//   2. 提取被挑战的子矩阵行 → prover_hint
//   3. merkle_tree::open → 发送 Merkle 路径
//   4. verifier 端 merkle_tree::verify → 验证路径 + 重建根
//
// 域类型:
//   Source (F)  — 基域 (Goldilocks / GoldilocksExt2 / GoldilocksExt3)
//   Target (G) — 扩展域, 用于域外采样和求值 (通过 Embedding M 嵌入)
//   M          — 嵌入映射 F → G (Identity / Basefield / Compose)
// =============================================================================

//IRS是一种编码技术:将多个多项式的系数按交错方式排列,再通过NTT做RS编码.
//irs_commit模块就是用交错RS编码来实现多项式承诺(commitment)的———编码后的码字(codeword)交给Merkle Tree承载体,然后再做随机采样验证

#include "../algebra/embedding.hpp"
#include "../algebra/linear_form.hpp"
#include "../algebra/ntt/utils.hpp"
#include "../algebra/ntt/cooley_tukey.hpp"
#include "../algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "../algebra/ntt/mod_ntt.hpp"
#include "../algebra/utilities.hpp"
#include "../hash/blake3_engine.hpp"
#include "../hash/hash_engine.hpp"
#include "../hash/sha2_engine.hpp"
#include "../utils.hpp"
#include "challenge_indices.hpp"
#include "merkle_tree.hpp"
#include "matrix_commit.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <optional>
#include <vector>

namespace whir::protocols::irs_commit {

inline const ::whir::hash::HashEngine& hash_engine_for(::whir::EngineId id) {
    if (id == ::whir::hash::ENGINE_ID_BLAKE3) {
        static const ::whir::hash::Blake3 blake3;
        return blake3;
    }
    if (id == ::whir::hash::ENGINE_ID_SHA2) {
        static const ::whir::hash::Sha2 sha2;
        return sha2;
    }
    static const ::whir::hash::Blake3 blake3;
    return blake3;
}

// =============================================================================
// Evaluations — 求值结果容器
//
// 存储一组求值点和对应的求值矩阵。矩阵的行数 = points.size(),
// 列数 = num_columns() = matrix.size() / points.size()。
//
// 对标 Rust: irs_commit::Evaluations<F>
// =============================================================================

template <typename F>
struct Evaluations {
    std::vector<F> points;   // 求值点列表 (每个点对应矩阵的一行)
    std::vector<F> matrix;   // 求值结果矩阵, 行主序 (row-major)

    std::size_t num_points() const { return points.size(); } //求指点列表大小

    // matrix 是行主序: 每行 num_columns() 个元素, 共 num_points() 行
    //每行多少个元素
    std::size_t num_columns() const {
        return points.empty() ? 0 : matrix.size() / points.size();
    }

    // 把基域的求值 lift 到扩展域 (用于跨域协议)
    template <typename M> //M一般为Goldilocks64_Ext2或Goldilocks64_Ext3
    Evaluations<typename M::Target> lift(const M& emb) const {
        return {
            ::whir::algebra::lift<M>(emb, points),
            ::whir::algebra::lift<M>(emb, matrix),
        };
    }

    // 为每个求值点构造 UnivariateEvaluation 对象 (用于线性形式评估)
    std::vector<::whir::algebra::UnivariateEvaluation<F>>
    evaluators(std::size_t size) const {
        std::vector<::whir::algebra::UnivariateEvaluation<F>> evals; //构造一个动态数组
        evals.reserve(points.size()); //size大小
        //传入参数(p,size)构造UnivariateEvaluation
        for (const auto& p : points) evals.emplace_back(p, size); //
        return evals;
    }

    // 用 weights 对每行做内积: result[i] = dot(matrix.row(i), weights)
    std::vector<F> values(std::span<const F> weights) const {
        std::vector<F> result(num_points());
        std::size_t cols = num_columns(); //num_columns代表每行有多少个元素(即列数)
        for (std::size_t i = 0; i < num_points(); ++i)
            result[i] = ::whir::algebra::dot<F>(
                //计算偏移量i*cols,截取长度为cols的一段数据,提取出matrix的第i行,然后与weight进行点积运算
                std::span<const F>{matrix}.subspan(i * cols, cols), weights);
        return result;
    }
};

// =============================================================================
// Witness — commit() 的返回值, 包含承诺所需的所有数据
//
// 对标 Rust: irs_commit::Witness<F, G>
// =============================================================================

template <typename F, typename G>
struct Witness {
    std::vector<F> matrix;                 // RS 编码后的完整矩阵 (codeword_length 行 × num_cols 列, 行主序)
    merkle_tree::Witness matrix_witness;   // Merkle 树见证 (全部节点, 用于后续 open 时生成路径)
    Evaluations<G> out_of_domain;          // 域外求值结果 (points + matrix)
    std::size_t num_vectors() const { return out_of_domain.num_columns(); }
};

// =============================================================================
// Commitment — receive_commitment() 的返回值, verifier 端持有的精简承诺
//
// 对标 Rust: irs_commit::Commitment<G>
// =============================================================================

template <typename G>
struct Commitment {
    merkle_tree::Commitment matrix_commitment;  // Merkle 树根哈希 (verifier 据此验证打开)
    Evaluations<G> out_of_domain;               // 域外求值 (verifier 需要验证其正确性)
    std::size_t num_vectors() const { return out_of_domain.num_columns(); } //out_of_domain的列数
};

// =============================================================================
// Config — IRS 承诺的配置参数
//
// 对标 Rust: irs_commit::Config<M>
//
// 核心参数:
//   - num_vectors: 要承诺的向量数量
//   - vector_size: 每个向量的长度 (系数个数)
//   - interleaving_depth: 交错深度 (把多个向量交织编码, 提高编码效率)
//   - codeword_length: RS 码字长度 (编码后的行数)
//   - in_domain_samples / out_domain_samples: 域内/域外采样数 (决定安全级别)
//   - deduplicate_in_domain: 是否对域内采样去重 (减小 proof 大小, 但改变 transcript pattern)
//
// 码率 rate = message_length / codeword_length, 其中 message_length = vector_size / interleaving_depth。
// 较低码率 → 更强纠错能力 → 更少采样数 → 但对证明者更昂贵。
// =============================================================================

template <typename M>
struct Config {
    using Source = typename M::Source;   // 基域类型 (F)
    using Target = typename M::Target;   // 扩展域类型 (G)

    M embedding_val;                              // 嵌入映射 F → G (用于域外求值)
    std::size_t num_vectors = 0;                  // 向量数量
    std::size_t vector_size = 0;                  // 每个向量的长度
    std::size_t codeword_length = 0;              // RS 码字长度 (编码后的行数, 必须是 NTT 友好大小)
    std::size_t interleaving_depth = 0;           // 交错深度 (vector_size 必须是它的倍数)
    merkle_tree::Config matrix_commit_mt;          // 矩阵承诺的 Merkle 树配置 (层数 + 哈希引擎)
    std::size_t matrix_commit_num_cols = 0;       // 矩阵承诺的列数 (= num_vectors * interleaving_depth)
    double johnson_slack = 0.0;                   // Johnson 边界的松弛因子 (0 = 唯一解码)
    std::size_t in_domain_samples = 0;            // 域内采样数 (prover 需要打开这些行)
    std::size_t out_domain_samples = 0;           // 域外采样数 (prover 需要计算域外求值)
    bool deduplicate_in_domain = false;           // 是否对域内采样去重

    const M* embedding() const { return &embedding_val; }

    // 编码矩阵的列数: 每个原始向量被拆成 interleaving_depth 个码字分量
    std::size_t num_cols() const { return matrix_commit_num_cols; }

    // 编码矩阵的总大小: codeword_length 行 × num_cols 列
    std::size_t size() const { return codeword_length * matrix_commit_num_cols; }

    // 每条消息的长度 (编码前): vector_size / interleaving_depth
    std::size_t message_length() const { return vector_size / interleaving_depth; }

    // 码率 = 消息长度 / 码字长度 (∈ (0, 1], 越低越冗余)
    double rate() const { return static_cast<double>(message_length()) / static_cast<double>(codeword_length); }

    // 是否为唯一解码模式 (无域外采样, 无 Johnson 松弛)
    bool unique_decoding() const { return out_domain_samples == 0 && johnson_slack == 0.0; }

    // 获取 NTT 域的生成元 (用于计算域内挑战点)
    // generator^k 对应域中第 k 个求值点
    Source generator() const {
        auto g = ::whir::algebra::ntt::generator<Source>(codeword_length);
        assert(g.has_value() && "codeword_length exceeds NTT domain");
        return *g;
    }

    // ---- 安全分析 (Soundness Analysis) ----

    // 列表解码的列表大小上界 (Johnson bound): 1 / (2*η*√ρ)
    double list_size() const {
        if (unique_decoding()) return 1.0;
        return 1.0 / (2.0 * johnson_slack * std::sqrt(rate()));
    }

    // 域外采样的逐轮安全性 (bits): -log2(L choose 2) - s * log2(per_sample)
    double rbr_ood_sample(double field_size_bits) const {
        double L = list_size();
        double l_choose_2 = L * (L - 1.0) / 2.0;
        double log_per_sample = std::log2(static_cast<double>(vector_size - 1)) - field_size_bits;
        return -std::log2(l_choose_2) - static_cast<double>(out_domain_samples) * log_per_sample;
    }

    // 域内查询的逐轮安全性 (bits): q * (-log2(per_sample))
    double rbr_queries() const {
        double per_sample;
        if (unique_decoding()) {
            per_sample = ((1.0 + rate()) * 0.5);  // (1+ρ)/2 → 1 - δ = 1 - per_sample
        } else {
            per_sample = std::sqrt(rate()) + johnson_slack;  // √ρ + η
        }
        return static_cast<double>(in_domain_samples) * (-std::log2(per_sample));
    }

    // 折叠邻近间隙项 (proximity gaps) 的安全性 (bits)
    double rbr_soundness_fold_prox_gaps(double field_size_bits) const {
        double log_inv_rate = -std::log2(rate());
        double log_k = std::log2(static_cast<double>(message_length()));
        double error;
        if (unique_decoding()) {
            error = log_k + log_inv_rate;
        } else {
            // 7*log2(10) + 3.5*log_inv_rate + 2*log_k
            constexpr double LOG2_10 = 3.321928094887362;
            error = 7.0 * LOG2_10 + 3.5 * log_inv_rate + 2.0 * log_k;
        }
        return field_size_bits - error;
    }

    // ---- from_params: 从安全参数构造 Config ----
    // 对标 Rust: irs_commit::Config::new()
    //
    // 输入:
    //   security_target    — 目标安全级别 (bits)
    //   unique_dec         — 是否唯一解码
    //   hash_id            — 哈希引擎 ID
    //   num_vec            — 向量数量
    //   vec_size           — 向量长度 (= initial_size for initial, = 1<<num_vars for rounds)
    //   il_depth           — 交错深度
    //   rate_val            — 码率
    //   field_size_bits    — 扩展域大小 (bits)
    static Config from_params(
        double security_target,
        bool unique_dec,
        ::whir::EngineId hash_id,
        std::size_t num_vec,
        std::size_t vec_size,
        std::size_t il_depth,
        double rate_val,
        double field_size_bits)
    {
        Config c;
        c.num_vectors = num_vec;
        c.vector_size = vec_size;
        c.interleaving_depth = il_depth;
        c.deduplicate_in_domain = false;

        assert(vec_size % il_depth == 0);
        assert(rate_val > 0.0 && rate_val <= 1.0);

        std::size_t msg_len = vec_size / il_depth;
        c.codeword_length = static_cast<std::size_t>(std::ceil(static_cast<double>(msg_len) / rate_val));
        double actual_rate = static_cast<double>(msg_len) / static_cast<double>(c.codeword_length);

        // Johnson 松弛因子 η = √ρ / 20 (仅列表解码)
        c.johnson_slack = unique_dec ? 0.0 : std::sqrt(actual_rate) / 20.0;

        // 域外采样数
        if (unique_dec) {
            c.out_domain_samples = 0;
        } else {
            double L = 1.0 / (2.0 * c.johnson_slack * std::sqrt(actual_rate));
            double l_choose_2 = L * (L - 1.0) / 2.0;
            double log_per_sample = field_size_bits - std::log2(static_cast<double>(vec_size - 1));
            assert(log_per_sample > 0.0);
            c.out_domain_samples = static_cast<std::size_t>(
                std::ceil((security_target + std::log2(l_choose_2)) / log_per_sample));
            if (c.out_domain_samples < 1) c.out_domain_samples = 1;
        }

        // 域内采样数
        {
            double per_sample;
            if (unique_dec) {
                per_sample = ((1.0 + actual_rate) * 0.5);  // (1+ρ)/2
            } else {
                per_sample = std::sqrt(actual_rate) + c.johnson_slack;
            }
            c.in_domain_samples = static_cast<std::size_t>(
                std::ceil(security_target / (-std::log2(per_sample))));
        }

        c.matrix_commit_num_cols = il_depth * num_vec;
        c.matrix_commit_mt.num_leaves = c.codeword_length;
        c.matrix_commit_mt.layers.assign(
            merkle_tree::layers_for_size(c.codeword_length),
            merkle_tree::LayerConfig{hash_id});
        return c;
    }

    // ==========================================================================
    // commit — 承诺一组向量 (prover 侧)
    //
    // 对标 Rust: Config::commit()
    //
    // 输入: vectors — num_vectors 个长度为 vector_size 的基域向量
    // 输出: Witness{matrix, matrix_witness, out_of_domain}
    //
    // 步骤详解:
    //   1. interleaved_rs_encode(vectors, codeword_length, interleaving_depth)
    //      → 把 vectors 重排为 codeword_length 行 × num_cols 列, 每列做 NTT RS 编码
    //   2. commit_leaves(matrix, num_cols, leaves)
    //      → 矩阵每行 LE 编码为字节, 哈希为 32B 叶子
    //   3. merkle_tree::commit(prover_state, leaves)
    //      → 自底向上构建 Merkle 树, 通过 transcript 发送 root 承诺
    //   4. 域外采样 + 求值
    //      a) transcript 挤出 out_domain_samples 个扩展域随机点
    //      b) 对每个原始向量在每个点做 mixed_univariate_evaluate → 扩展域值
    //      c) 将求值结果通过 transcript 发送给 verifier
    //      → Evaluations<Target>
    // ==========================================================================
    template <typename Transcript>
    Witness<Source, Target> commit(
        Transcript& prover_state,
        std::span<const std::span<const Source>> vectors) const //多项式系数
    {
        assert(vectors.size() == num_vectors); //vector大小是否等于多项式个数
        for (const auto& v : vectors) assert(v.size() == vector_size); //每个多项式大小==向量长度
        const ::whir::EngineId matrix_hash_id = matrix_commit_mt.layers.empty()
            ? ::whir::hash::ENGINE_ID_BLAKE3
            : matrix_commit_mt.layers.back().hash_id;

        // 1. Interleaved RS encode — 把原始向量编码为码字矩阵
        //    不同域类型需要不同的 NTT engine (Goldilocks/Ext2/Ext3 的二阶性不同)
        std::vector<Source> matrix;

        //matrix=
        //[
        //  A00, A10, B00, B10,  // 对应 x_0 点的所有求值，将作为 Merkle Tree 的 Leaf 0
        //  A01, A11, B01, B11,  // 对应 x_1 点的所有求值，将作为 Merkle Tree 的 Leaf 1
        //  A02, A12, B02, B12,  // 对应 x_2 点的所有求值，将作为 Merkle Tree 的 Leaf 2
        //  A03, A13, B03, B13   // 对应 x_3 点的所有求值，将作为 Merkle Tree 的 Leaf 3
        //]
        if constexpr (std::is_same_v<Source, ::whir::algebra::Goldilocks>) { //is_same_v判断Source是哪种类型 if constexpr表示只会编译条件为true的分支
            matrix = ::whir::algebra::ntt::interleaved_rs_encode<Source>(
                ::whir::algebra::ntt::goldilocks_engine(), vectors, codeword_length, interleaving_depth);
        } else if constexpr (std::is_same_v<Source, ::whir::algebra::GoldilocksExt2>) {
            matrix = ::whir::algebra::ntt::interleaved_rs_encode<Source>(
                ::whir::algebra::ntt::goldilocks_ext2_engine(), vectors, codeword_length, interleaving_depth);
        } else if constexpr (std::is_same_v<Source, ::whir::algebra::GoldilocksExt3>) {
            matrix = ::whir::algebra::ntt::interleaved_rs_encode<Source>(
                ::whir::algebra::ntt::goldilocks_ext3_engine(), vectors, codeword_length, interleaving_depth);
        } else {
            static_assert(sizeof(Source) == 0, "IRS commit: unsupported field type");
        }

        // 2. 逐行编码 + 哈希 → 叶子哈希列表
        //    每行 = num_cols 个域元素, 每个元素 LE 编码为 8/16/24 字节
        //    hash_many 把整个扁平字节缓冲按行切分, 每行独立哈希
        std::size_t num_rows = codeword_length; //码字长度
        ::whir::hash::Blake3 blake3_engine;
        ::whir::hash::Sha2 sha2_engine;
        const ::whir::hash::HashEngine& leaf_engine =
            (matrix_hash_id == ::whir::hash::ENGINE_ID_SHA2)
                ? static_cast<const ::whir::hash::HashEngine&>(sha2_engine)
                : static_cast<const ::whir::hash::HashEngine&>(blake3_engine);
        std::vector<::whir::hash::Hash> leaves(num_rows);
        ::whir::protocols::matrix_commit::commit_leaves<Source>(
            //leaves的大小是num_rows,leave中的每一个是hash(per*num_col)
            leaf_engine, matrix, num_cols(), leaves);

        // 3. Merkle 树承诺 — 从叶子构建树, 通过 transcript 发送 root
        //    merkle_tree::commit 内部做:
        //      a) build_tree: 叶子 → 逐层哈希 → 完整树节点
        //      b) prover_message(root): 发送根哈希作为承诺
        //    返回的 Witness 包含全部节点, 后续 open 时用于生成 Merkle 路径

        //使用SHA-256将一组叶子节点生成一颗Merkle Tree，并生成Witness
        auto mt_witness = merkle_tree::commit(prover_state, //prover状态
            matrix_commit_mt, //Merkle Tree配置
            std::move(leaves),//叶子

            //这个下面是一个lambda函数
            [&blake3_engine, &sha2_engine](::whir::EngineId id) -> const ::whir::hash::HashEngine& {
                if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_engine;
                return blake3_engine;
            });
        //返回w,Merkle Tree的见证

        // 4. 域外采样 — 挤出随机扩展域点, 对每个原始向量做单变量求值
        //    域外采样用于检测距离 (proximity testing): 如果原始向量不是合法码字,
        //    则域外求值大概率暴露不一致。每个域外点贡献的安全性由 embedding field size 和 rate 决定。

        //Prover通过随机获取几个域外的挑战点,然后将之前承诺的多项式在这些点上求值,并写入transcript中,最后返回完整承诺和求值数据
        auto oods_points = prover_state.template verifier_message_vec<Target>(out_domain_samples);//out_domain_samples是域外采样数,返回count个数
        std::vector<Target> oods_matrix;
        oods_matrix.reserve(out_domain_samples * num_vectors); //matrix大小为(域外点个数*多项式个数)

        for (const auto& point : oods_points) { //遍历每个域外求值点
            for (const auto& vec : vectors) { //遍历每个多项式
                // mixed_univariate_evaluate: 在扩展域点 point 处评估基域向量 vec
                //   1. 把 vec 的基域系数 embed 到扩展域
                //   2. 对每个交错分量 (共 interleaving_depth 个) 独立求值
                //   3. 合并结果 → 单个扩展域值
                Target value = ::whir::algebra::mixed_univariate_evaluate<M>(
                    embedding_val, vec, point); //求每个多项式在域外点的值
                prover_state.prover_message(value);   // 发送域外求值 (prover同时吸入 sponge + 序列化)
                oods_matrix.push_back(value); //把value放入oods_matrix
            }
        }

        return {std::move(matrix), //matrix矩阵
            std::move(mt_witness), //Merkle Tree见证
                Evaluations<Target>{std::move(oods_points), //域外点
                    std::move(oods_matrix)}}; //域外点求值matrix
    }

    // ==========================================================================
    // receive_commitment — 接收承诺 (verifier 侧)
    //
    // 对标 Rust: Config::receive_commitment()
    //
    // verifier 不需要访问编码矩阵, 只需要:
    //   1. Merkle 树根 (通过 transcript 接收)
    //   2. 域外采样点 (从 transcript 挤出, 与 prover 相同的确定性值)
    //   3. 域外求值 (通过 transcript 接收 prover 发送的值)
    // ==========================================================================
    template <typename Transcript>
    Commitment<Target> receive_commitment(Transcript& verifier_state) const {
        // 1. 接收 Merkle 树根承诺 (prover 在 commit 时发送)
        auto matrix_commitment = merkle_tree::receive_commitment(verifier_state); //返回root

        // 2. 挤出域外采样点 (与 prover 相同的确定性随机点, 因为 sponge 状态同步)
        auto oods_points = verifier_state.template verifier_message_vec<Target>(out_domain_samples);//相同的域外点

        // 3. 接收域外求值 (prover 在 commit 第 4 步发送)
        std::vector<Target> oods_matrix(out_domain_samples * num_vectors); //一个矩阵大小是域外点个数*多项式个数
        for (auto& val : oods_matrix) //遍历oods_matrix
            if (!verifier_state.prover_message(val)) return {};  // proof 不足 → 失败

        return {matrix_commitment, //root
                Evaluations<Target>{std::move(oods_points), //域外点
                    std::move(oods_matrix)}}; //域外求值matrix
    }

    // ==========================================================================
    // in_domain_challenges — 生成域内挑战索引和对应求值点
    //
    // 对标 Rust: Config::in_domain_challenges()
    //
    // 1. 通过 transcript 挤出 codeword_length 范围内的随机索引
    //    (challenge_indices 内部做: 挤出随机字节 → rejection sampling → 可选去重)
    // 2. 每个索引 i 对应求值点 generator^i (NTT 域中的第 i 个点)
    // ==========================================================================
    template <typename Transcript>
    std::pair<std::vector<std::size_t>, std::vector<Source>>
    in_domain_challenges(Transcript& transcript) const {
        // 挤出随机索引 (范围 [0, codeword_length), 可选去重)
        auto indices = ::whir::protocols::challenge_indices::challenge_indices(
            transcript,
            codeword_length,  //叶子数(码长)
            in_domain_samples,  //挑战索引个数
            deduplicate_in_domain); //是否去重

        // 索引 → 域中求值点: point = generator^index
        auto gen = generator(); //生成元
        std::vector<Source> points;
        points.reserve(indices.size());
        for (auto idx : indices)
            points.push_back(gen.pow(static_cast<std::uint64_t>(idx))); //points是一个vec,里面是point = generator^index
        return {std::move(indices), std::move(points)}; //返回pair(indices,points)
    }

    // ==========================================================================
    // open — 打开见证的域内求值 (prover 侧)
    //
    // 对标 Rust: Config::open()
    //
    // 支持一次打开多个见证 (多见证的求值矩阵水平拼接)。
    //
    // 步骤:
    //   1. in_domain_challenges → 挤出域内挑战索引
    //   2. 对每个 witness:
    //      a) 提取被挑战的子矩阵行 → prover_hint (子矩阵原始数据)
    //      b) merkle_tree::open → 发送 Merkle 路径 hints (验证根时所需的 sibling)
    //   3. 返回: 求值点 + 拼接后的子矩阵 (供上层协议使用)
    //
    // 输出矩阵布局:
    //   rows = indices.size(), cols = n_witnesses * num_cols()
    //   矩阵第 pi 行的第 [col_offset, col_offset+num_cols) 列 = 第 pi 个 witness 的被挑战行
    // ==========================================================================

    //Prover根据挑战索引,从Merkle Tree中抽查特定的叶子节点提取出原始数据然后生成proof发送给Verifier
    template <typename Transcript>
    Evaluations<Source> open(
        Transcript& prover_state,
        std::span<const Witness<Source, Target>*> witnesses_list) const //一个指针数组,每个指针指向一个Merkle见证,每个Witness对应一颗已经构造好的Merkle Tree
    {
        // 验证所有见证的尺寸一致性
        for (const auto* w : witnesses_list) {
            assert(w->matrix.size() == size()); //
            assert(w->out_of_domain.points.size() == out_domain_samples); //域外求值点个数
            assert(w->out_of_domain.matrix.size() == out_domain_samples * num_vectors);//域外矩阵求指点个数*多项式个数
        }

        // 1. 挤出域内挑战
        auto [indices, points] = in_domain_challenges(prover_state);

        // 多见证时, 求值矩阵水平拼接: 每行 stride = n_witnesses * num_cols() 列
        std::size_t n_witnesses = witnesses_list.size();  //Merkle 见证个数
        std::size_t stride = n_witnesses * num_cols();
        std::vector<Source> matrix(indices.size() * stride, Source::zero());

        std::size_t col_offset = 0;
        for (const auto* w : witnesses_list) {
            // 2a. 提取被挑战的行 → 子矩阵
            //     子矩阵布局: indices.size() 行 × num_cols() 列, 行主序
            std::vector<Source> submatrix;
            submatrix.reserve(indices.size() * num_cols());

            //假设indices=[6,7],假设num_cols=1
            for (std::size_t pi = 0; pi < indices.size(); ++pi) {
                
                // 被挑战行的起始偏移 = 索引 × 列数
                //row_start=6,7
                std::size_t row_start = indices[pi] * num_cols();
                for (std::size_t c = 0; c < num_cols(); ++c) //遍历每一列

                    //submatrix[0]=matrix[6],submatrix[1]=matrix[7] submatrix(两行一列)
                    submatrix.push_back(w->matrix[row_start + c]);

                // 同时拼接到输出矩阵 (水平拼接)
                for (std::size_t c = 0; c < num_cols(); ++c)
                    //matrix[0]=w->matrix[6],matrix[1]=w->matrix[7]
                    matrix[pi * stride + col_offset + c] = w->matrix[row_start + c];
            }

            // 发送子矩阵 hint (verifier 需要用来重建叶子哈希)
            //prover序列化submatrix
            prover_state.prover_hint(submatrix);

            // 2b. Merkle 树打开 — 发送从叶子到根的路径 (sibling hashes)
            //     verifier 用这些路径验证被挑战行确实在承诺的树中
            merkle_tree::open(prover_state, matrix_commit_mt,
                              w->matrix_witness, std::span<const std::size_t>{indices});

            col_offset += num_cols();
        }

        return {std::move(points), std::move(matrix)}; 
    }

    // ==========================================================================
    // verify — 验证域内求值 (verifier 侧)
    //
    // 对标 Rust: Config::verify()
    //
    // 对每个承诺:
    //   1. 接收子矩阵 hint (prover 发送的原始行数据)
    //   2. 对子矩阵重新计算叶子哈希 (commit_leaves)
    //   3. merkle_tree::verify → 用叶子 + Merkle 路径 hints 重建 root, 与承诺的 root 比对
    //   4. 水平拼接子矩阵到输出 (供上层协议使用)
    // ==========================================================================
    template <typename Transcript>
    Evaluations<Source> verify(
        Transcript& verifier_state,
        std::span<const Commitment<Target>*> commitments_list) const
    {
        // 验证所有承诺的域外数据一致性
        for (const auto* c : commitments_list) {
            assert(c->out_of_domain.points.size() == out_domain_samples);
            assert(c->out_of_domain.matrix.size() == num_vectors * out_domain_samples);
        }

        // 挤出域内挑战 (与 prover 相同的确定性索引)
        auto [indices, points] = in_domain_challenges(verifier_state);
        const ::whir::EngineId matrix_hash_id = matrix_commit_mt.layers.empty()
            ? ::whir::hash::ENGINE_ID_BLAKE3
            : matrix_commit_mt.layers.back().hash_id;

        std::size_t n_commitments = commitments_list.size();
        std::size_t stride = n_commitments * num_cols();
        std::vector<Source> matrix(indices.size() * stride, Source::zero());

        std::size_t col_offset = 0;
        for (const auto* c : commitments_list) {
            
            // 1. Verifier从hints中反序列化接收子矩阵 hint — prover 声称被挑战行的值
            std::vector<Source> submatrix;
            if (!verifier_state.prover_hint(submatrix)) return {};

            // 2. 对收到的子矩阵重新计算叶子哈希
            //    这步确保 prover 发送的子矩阵值与当初 commit 时一致:
            //    如果 prover 修改了行数据, 重算的叶子哈希会和 Merkle 路径不匹配

            //v_leaf_hash[0] (对应索引 6) = 73654ec5a06282fe07ff42cd0c21d93f5c3ec2416aecc8bff51bbf55f9bba8ed
            //v_leaf_hash[1] (对应索引 7) = f8d291b42b4d1ae77853faf228d10619adf70f4e1b513e6a797920cb681cadc7
            ::whir::hash::Blake3 blake3_engine;
            ::whir::hash::Sha2 sha2_engine;
            const ::whir::hash::HashEngine& verify_leaf_engine =
                (matrix_hash_id == ::whir::hash::ENGINE_ID_SHA2)
                    ? static_cast<const ::whir::hash::HashEngine&>(sha2_engine)
                    : static_cast<const ::whir::hash::HashEngine&>(blake3_engine);
            std::vector<::whir::hash::Hash> leaf_hashes(indices.size()); //索引个数
            ::whir::protocols::matrix_commit::commit_leaves<Source>(
                verify_leaf_engine, submatrix, num_cols(), leaf_hashes);

            // 3. Merkle 树验证 — 用叶子哈希 + Merkle 路径 hints 重建 root
            //    merkle_tree::verify 内部:
            //      a) 接收 Merkle 路径 hints (sibling hashes)
            //      b) 从叶子 + hints 自底向上逐层哈希
            //      c) 比对重建的 root 与承诺的 root
            auto engine_lookup = [&blake3_engine, &sha2_engine](::whir::EngineId id) -> const ::whir::hash::HashEngine& {
                if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_engine;
                return blake3_engine;
            };

            //验证与root哈希是否一致
            if (!merkle_tree::verify(verifier_state, matrix_commit_mt,
                                     c->matrix_commitment, //root哈希
                                     std::span<const std::size_t>{indices},//索引indices=6,7
                                     std::span<const ::whir::hash::Hash>{leaf_hashes},
                                     engine_lookup)) {
                return {};  // 验证失败 → 返回空结果
            }

            // 4. 水平拼接 — 把当前承诺的子矩阵拷贝到输出矩阵的对应列区域
            if (stride > 0 && num_cols() > 0) {
                for (std::size_t pi = 0; pi < indices.size(); ++pi) {
                    for (std::size_t c = 0; c < num_cols(); ++c) {

                        //matrix[0]=submatrix[0],matrix[1]=submatrix[1]
                        matrix[pi * stride + col_offset + c] =
                            submatrix[pi * num_cols() + c];
                    }
                }
            }

            col_offset += num_cols();
        }

        return {std::move(points), std::move(matrix)};
    }
};

// =============================================================================
// num_in_domain_queries — 计算达到目标安全性所需的域内查询数
//
// 对标 Rust: irs_commit::num_in_domain_queries()
//
// 唯一解码 (unique_decoding=true):  δ = (1 + ρ) / 2, 每查询安全度 = -log2(δ)
// 列表解码 (unique_decoding=false):  δ = 1 - √ρ - η, η = √ρ / 20
//
// 所需查询数 q 满足: q ≥ security_target / (-log2(per_sample))
// =============================================================================
inline double num_in_domain_queries(bool unique_decoding, double security_target, double rate) {
    // Johnson 松弛因子 (仅列表解码模式)
    double johnson_slack = unique_decoding ? 0.0 : std::sqrt(rate) / 20.0;

    // 每个查询的"错误概率" (prover 骗过 verifier 的概率)
    double per_sample = unique_decoding
        ? (1.0 + rate) / 2.0              // 唯一解码: δ = (1 + ρ) / 2
        : std::sqrt(rate) + johnson_slack; // 列表解码: δ = √ρ + η

    // q = ceil(security_target / -log2(per_sample))
    return std::ceil(security_target / (-std::log2(per_sample)));
}

} // namespace whir::protocols::irs_commit
