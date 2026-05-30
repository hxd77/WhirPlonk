#pragma once

// ============================================================================
// irs_commit.hpp — 交错 Reed-Solomon 承诺协议
//
// 通过交错 NTT 将多个向量编码为 RS 码字，逐行通过 Merkle 树承诺，
// 并支持域内和域外打开。这是 WHIR 协议的核心多项式承诺组件。
//
// 数据流:
//   原始向量 (num_vectors x vector_size)
//     | interleaved_rs_encode（NTT RS 编码）
//   编码矩阵 (codeword_length x [num_vectors * interleaving_depth])
//     | commit_leaves（逐行 LE 编码 + 哈希）
//   叶子哈希 (codeword_length 个 Hash)
//     | merkle_tree::commit（构建树，通过 transcript 发送根）
//   Merkle 见证（完整节点数组）
//     | 域外采样（verifier_message_vec 挤压随机点）
//   域外求值（mixed_univariate_evaluate）
//     -> Witness{matrix, matrix_witness, out_of_domain}
//
// 域内打开（open/verify）:
//   1. 从 transcript 挤压挑战索引
//   2. 提取被挑战的子矩阵行 -> prover_hint
//   3. merkle_tree::open -> 发送 Merkle 兄弟哈希
//   4. 验证者: merkle_tree::verify -> 重建根，与承诺比较
//
// 域类型:
//   Source (F) — 基域（Goldilocks / GoldilocksExt2 / GoldilocksExt3）
//   Target (G) — 扩域，用于域外采样/求值
//   M          — 嵌入映射 F -> G（Identity / Basefield / Compose）
//
// 对应 Rust 文件: src/protocols/irs_commit.rs
// ============================================================================

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
#include "../profiling.hpp"
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

/// 将 EngineId 解析为具体的 HashEngine 引用。
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

// ============================================================================
// Evaluations — 求值结果容器
//
// 存储一组求值点和对应的求值矩阵。
// 矩阵布局: 行优先，rows = points.size()，cols = num_columns()。
//
// 对应 Rust: irs_commit::Evaluations<F>
// ============================================================================

template <typename F>
struct Evaluations {
    std::vector<F> points;   // 求值点:[z₁, z₂, ..., zₖ]
    std::vector<F> matrix;   // 求值矩阵: 行优先，每行对应一个点

    std::size_t num_points() const { return points.size(); }

    /// 每行列数 = matrix.size() / points.size()。
    std::size_t num_columns() const {
        return points.empty() ? 0 : matrix.size() / points.size();
    }

    /// 将基域求值提升到扩域（用于跨域协议）。
    template <typename M>
    Evaluations<typename M::Target> lift(const M& emb) const {
        return {
            ::whir::algebra::lift<M>(emb, points),
            ::whir::algebra::lift<M>(emb, matrix),
        };
    }

    /// 构造用于线性形式求值的 UnivariateEvaluation 对象。
    std::vector<::whir::algebra::UnivariateEvaluation<F>>
    evaluators(std::size_t size) const {
        std::vector<::whir::algebra::UnivariateEvaluation<F>> evals;
        evals.reserve(points.size());
        for (const auto& p : points) evals.emplace_back(p, size);
        return evals;
    }

    /// 逐行加权内积: result[i] = dot(matrix.row(i), weights)。
    std::vector<F> values(std::span<const F> weights) const {
        std::vector<F> result(num_points());
        std::size_t cols = num_columns();
        for (std::size_t i = 0; i < num_points(); ++i)
            result[i] = ::whir::algebra::dot<F>(
                std::span<const F>{matrix}.subspan(i * cols, cols), weights);
        return result;
    }
};

// ============================================================================
// Witness — commit() 返回值，包含打开所需的全部信息
//
// 对应 Rust: irs_commit::Witness<F, G>
// ============================================================================

template <typename F, typename G>
struct Witness {
    std::vector<F> matrix;                 // RS 编码矩阵（codeword_length x num_cols，行优先）
    merkle_tree::Witness matrix_witness;   // Merkle 树见证（所有节点，用于生成 open-path）
    std::vector<::whir::hash::Hash> matrix_leaves; // 可选叶子哈希，用于 GPU/混合 open-path
    Evaluations<G> out_of_domain;          // 域外求值结果
    std::size_t num_vectors() const { return out_of_domain.num_columns(); }
};

// ============================================================================
// Commitment — receive_commitment() 返回值，验证者端紧凑形式
//
// 对应 Rust: irs_commit::Commitment<G>
// ============================================================================

template <typename G>
struct Commitment {
    merkle_tree::Commitment matrix_commitment;  // Merkle 根哈希
    Evaluations<G> out_of_domain;               // 域外求值（验证者检查正确性）
    std::size_t num_vectors() const { return out_of_domain.num_columns(); }
};

// ============================================================================
// Config — IRS 承诺参数
//
// 对应 Rust: irs_commit::Config<M>
//
// 关键参数:
//   num_vectors         — 待承诺的向量数量
//   vector_size         — 每个向量的长度（系数个数）
//   interleaving_depth  — 交错深度（多个向量交织在一起）
//   codeword_length     — RS 码字长度（NTT 友好大小）
//   in_domain_samples   — 域内查询次数（决定安全性）
//   out_domain_samples  — 域外采样次数
//   deduplicate_in_domain — 是否对域内采样去重
//
// 码率 = message_length / codeword_length，其中 message_length = vector_size / interleaving_depth。
// 码率越低 -> 纠错能力越强 -> 所需采样更少 -> 但证明者计算代价更高。
// ============================================================================

template <typename M>
struct Config {
    using Source = typename M::Source;   // 基域 (F)
    using Target = typename M::Target;   // 扩域 (G)

    M embedding_val;                              // 嵌入映射 F -> G
    std::size_t num_vectors = 0;
    std::size_t vector_size = 0;
    std::size_t codeword_length = 0;              // RS 码字长度（编码后的行数）
    std::size_t interleaving_depth = 0;           // vector_size 必须是此值的倍数
    merkle_tree::Config matrix_commit_mt;          // 矩阵承诺的 Merkle 树配置
    std::size_t matrix_commit_num_cols = 0;       // = num_vectors * interleaving_depth
    double johnson_slack = 0.0;                   // Johnson 界松弛量（0 = 唯一解码）
    std::size_t in_domain_samples = 0;
    std::size_t out_domain_samples = 0;
    bool deduplicate_in_domain = false;

    const M* embedding() const { return &embedding_val; }

    /// 编码矩阵的列数。
    std::size_t num_cols() const { return matrix_commit_num_cols; }

    /// 编码矩阵总大小: codeword_length x num_cols。
    std::size_t size() const { return codeword_length * matrix_commit_num_cols; }

    /// 编码前的消息长度: vector_size / interleaving_depth。
    std::size_t message_length() const { return vector_size / interleaving_depth; }

    /// 码率 = message_length / codeword_length，取值范围 (0, 1]。
    double rate() const { return static_cast<double>(message_length()) / static_cast<double>(codeword_length); }

    /// 是否为唯一解码模式（无 OOD 采样，无 Johnson 松弛）。
    bool unique_decoding() const { return out_domain_samples == 0 && johnson_slack == 0.0; }

    /// NTT 域生成元: generator^k 是第 k 个求值点。
    Source generator() const {
        auto g = ::whir::algebra::ntt::generator<Source>(codeword_length);
        assert(g.has_value() && "codeword_length exceeds NTT domain");
        return *g;
    }

    // ---- 安全性分析 ----

    /// 列表解码列表大小上界（Johnson 界）: 1 / (2*eta*sqrt(rho))。
    double list_size() const {
        if (unique_decoding()) return 1.0;
        return 1.0 / (2.0 * johnson_slack * std::sqrt(rate()));
    }

    /// 每轮域外采样的安全性（比特）。
    /// = -log2(L choose 2) - s * log2(per_sample)
    double rbr_ood_sample(double field_size_bits) const {
        double L = list_size();
        double l_choose_2 = L * (L - 1.0) / 2.0;
        double log_per_sample = std::log2(static_cast<double>(vector_size - 1)) - field_size_bits;
        return -std::log2(l_choose_2) - static_cast<double>(out_domain_samples) * log_per_sample;
    }

    /// 每轮域内查询的安全性（比特）。
    /// = q * (-log2(per_sample))
    double rbr_queries() const {
        double per_sample;
        if (unique_decoding()) {
            per_sample = ((1.0 + rate()) * 0.5);  // (1+rho)/2
        } else {
            per_sample = std::sqrt(rate()) + johnson_slack;  // sqrt(rho) + eta
        }
        return static_cast<double>(in_domain_samples) * (-std::log2(per_sample));
    }

    /// 近间隙折叠安全性项（比特）。
    double rbr_soundness_fold_prox_gaps(double field_size_bits) const {
        double log_inv_rate = -std::log2(rate());
        double log_k = std::log2(static_cast<double>(message_length()));
        double error;
        if (unique_decoding()) {
            error = log_k + log_inv_rate;
        } else {
            constexpr double LOG2_10 = 3.321928094887362;
            error = 7.0 * LOG2_10 + 3.5 * log_inv_rate + 2.0 * log_k;
        }
        return field_size_bits - error;
    }

    // ---- from_params: 从安全参数构造 Config ----
    //
    // 对应 Rust: irs_commit::Config::new()
    //
    // @param security_target  目标安全级别（比特）
    // @param unique_dec       是否使用唯一解码
    // @param hash_id          哈希引擎 ID
    // @param num_vec          向量数量
    // @param vec_size         向量长度
    // @param il_depth         交错深度
    // @param rate_val         码率
    // @param field_size_bits  扩域大小（比特）
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

        // Johnson 松弛 eta = sqrt(rho) / 20（仅列表解码时使用）
        c.johnson_slack = unique_dec ? 0.0 : std::sqrt(actual_rate) / 20.0;

        // 域外采样次数
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

        // 域内采样次数
        {
            double per_sample;
            if (unique_dec) {
                per_sample = ((1.0 + actual_rate) * 0.5);  // (1+rho)/2
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

    // =========================================================================
    // commit — 承诺一组向量（证明者端）
    //
    // 对应 Rust: Config::commit()
    //
    // @param vectors  num_vectors 个 span，每个长度为 vector_size
    // @return Witness{matrix, matrix_witness, out_of_domain}
    //
    // 步骤:
    //   1. interleaved_rs_encode: 将向量重排为 codeword_length x num_cols，
    //      对每个交错分量应用 NTT RS 编码
    //   2. commit_leaves: 逐行 LE 编码，哈希为 32B 叶子
    //   3. merkle_tree::commit: 自底向上 Merkle 树，通过 transcript 发送根
    //   4. 域外采样 + 求值:
    //      a) 从 transcript 挤压 out_domain_samples 个随机扩域点
    //      b) 对每个原始向量在每个点处计算 mixed_univariate_evaluate
    //      c) 通过 transcript 发送求值结果
    // =========================================================================
    template <typename Transcript>
    Witness<Source, Target> commit(
        Transcript& prover_state,
        std::span<const std::span<const Source>> vectors) const
    {
        assert(vectors.size() == num_vectors);
        for (const auto& v : vectors) assert(v.size() == vector_size);
        const ::whir::EngineId matrix_hash_id = matrix_commit_mt.layers.empty()
            ? ::whir::hash::ENGINE_ID_BLAKE3
            : matrix_commit_mt.layers.back().hash_id;

        // 1. 交错 RS 编码
        //    不同域类型需要不同的 NTT 引擎（Goldilocks/Ext2/Ext3
        //    具有不同的二次扩域结构）。
        std::vector<Source> matrix;
        {
            ::whir::profile::ScopedTimer timer("prover", size(), "witness_encoding");
            if constexpr (std::is_same_v<Source, ::whir::algebra::Goldilocks>) {
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
        }

        // 2. 逐行 LE 编码 + 哈希 -> 叶子哈希列表
        //    每行有 num_cols 个域元素，每个编码为 8/16/24 字节。
        //    hash_many 以行为单位处理整个平坦缓冲区。
        std::size_t num_rows = codeword_length;
        ::whir::hash::Blake3 blake3_engine;
        ::whir::hash::Sha2 sha2_engine;
        const ::whir::hash::HashEngine& leaf_engine =
            (matrix_hash_id == ::whir::hash::ENGINE_ID_SHA2)
                ? static_cast<const ::whir::hash::HashEngine&>(sha2_engine)
                : static_cast<const ::whir::hash::HashEngine&>(blake3_engine);
        std::vector<::whir::hash::Hash> leaves(num_rows);
        {
            ::whir::profile::ScopedTimer timer("prover", num_rows, "merkle_leaf_total");
            ::whir::protocols::matrix_commit::commit_leaves<Source>(
                leaf_engine, matrix, num_cols(), leaves);
        }

        // 3. Merkle 树承诺 — 从叶子构建树，发送根。
        // SHA-256 + CUDA 可只回传 root，并保留 leaves 供 open 时按需生成路径。
        std::vector<::whir::hash::Hash> matrix_leaves = leaves;
        merkle_tree::Witness mt_witness;
        bool committed_with_gpu_merkle_root = false;
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
        if (matrix_hash_id == ::whir::hash::ENGINE_ID_SHA2 &&
            ::whir::cuda::gpu_dispatch_enabled()) {
            ::whir::hash::Hash root{};
            ::whir::cuda::gpu_sha256_merkle_tree(
                reinterpret_cast<const std::uint8_t*>(leaves.data()),
                leaves.size(), root.data());
            prover_state.prover_message(root);
            committed_with_gpu_merkle_root = true;
        }
#endif
        if (!committed_with_gpu_merkle_root) {
            ::whir::profile::ScopedTimer timer("prover", num_rows, "merkle_build_total");
            mt_witness = merkle_tree::commit(prover_state,
                matrix_commit_mt,
                std::move(leaves),
                [&blake3_engine, &sha2_engine](::whir::EngineId id) -> const ::whir::hash::HashEngine& {
                    if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_engine;
                    return blake3_engine;
                });
        }

        // 4. 域外采样 — 挤压随机扩域点，对每个原始向量在每个点处求值。
        //    OOD 采样检测近似性: 如果原始向量不是有效码字，
        //    域外求值很可能不一致。
        auto oods_points = prover_state.template verifier_message_vec<Target>(out_domain_samples);
        std::vector<Target> oods_matrix;
        oods_matrix.reserve(out_domain_samples * num_vectors);

        {
            ::whir::profile::ScopedTimer timer("prover", vector_size, "ood_evaluation");
            for (const auto& point : oods_points) {
                for (const auto& vec : vectors) {
                    // mixed_univariate_evaluate: 将基域系数嵌入扩域，
                    // 独立求值每个交错分量，合并为单个扩域值。
                    Target value = ::whir::algebra::mixed_univariate_evaluate<M>(
                        embedding_val, vec, point);
                    prover_state.prover_message(value);
                    oods_matrix.push_back(value);
                }
            }
        }

        return {std::move(matrix),
                std::move(mt_witness),
                std::move(matrix_leaves),
                Evaluations<Target>{std::move(oods_points),
                    std::move(oods_matrix)}};
    }

    // =========================================================================
    // receive_commitment — 接收承诺（验证者端）
    //
    // 对应 Rust: Config::receive_commitment()
    //
    // 验证者不需要编码矩阵。它接收:
    //   1. Merkle 根（来自 transcript）
    //   2. OOD 采样点（确定性挤压，与证明者同步）
    //   3. OOD 求值（从 transcript 读取）
    // =========================================================================
    template <typename Transcript>
    Commitment<Target> receive_commitment(Transcript& verifier_state) const {
        // 1. 接收 Merkle 根
        auto matrix_commitment = merkle_tree::receive_commitment(verifier_state);

        // 2. 挤压 OOD 点（确定性，海绵状态已同步）
        auto oods_points = verifier_state.template verifier_message_vec<Target>(out_domain_samples);

        // 3. 读取证明者发送的 OOD 求值
        std::vector<Target> oods_matrix(out_domain_samples * num_vectors);
        for (auto& val : oods_matrix)
            if (!verifier_state.prover_message(val)) return {};  // 证明字节不足

        return {matrix_commitment,
                Evaluations<Target>{std::move(oods_points),
                    std::move(oods_matrix)}};
    }

    // =========================================================================
    // in_domain_challenges — 生成域内挑战索引和点
    //
    // 对应 Rust: Config::in_domain_challenges()
    //
    // 1. 从 transcript 挤压 [0, codeword_length) 范围内的随机索引
    //    （challenge_indices 处理拒绝采样 + 可选去重）
    // 2. 将每个索引 i 映射到求值点 generator^i
    // =========================================================================
    template <typename Transcript>
    std::pair<std::vector<std::size_t>, std::vector<Source>>
    in_domain_challenges(Transcript& transcript) const {
        auto indices = ::whir::protocols::challenge_indices::challenge_indices(
            transcript,
            codeword_length,
            in_domain_samples,
            deduplicate_in_domain);

        // 索引 -> NTT 域点: point = generator^index
        auto gen = generator();
        std::vector<Source> points;
        points.reserve(indices.size());
        for (auto idx : indices)
            points.push_back(gen.pow(static_cast<std::uint64_t>(idx)));
        return {std::move(indices), std::move(points)};
    }

    // =========================================================================
    // open — 揭示域内求值（证明者端）
    //
    // 对应 Rust: Config::open()
    //
    // 支持同时打开多个见证（求值矩阵水平拼接）。
    //
    // 步骤:
    //   1. in_domain_challenges -> 挤压挑战索引
    //   2. 对每个见证:
    //      a) 提取被挑战的行 -> prover_hint（子矩阵原始数据）
    //      b) merkle_tree::open -> 发送 Merkle 兄弟哈希
    //   3. 返回: 求值点 + 拼接后的子矩阵
    //
    // 输出矩阵布局:
    //   rows = indices.size()，cols = n_witnesses * num_cols()
    //   行 pi，列 [col_offset, col_offset+num_cols) = 见证 pi 的被挑战行
    // =========================================================================
    template <typename Transcript>
    Evaluations<Source> open(
        Transcript& prover_state,
        std::span<const Witness<Source, Target>*> witnesses_list) const
    {
        // 验证所有见证具有一致的维度
        for (const auto* w : witnesses_list) {
            assert(w->matrix.size() == size());
            assert(w->out_of_domain.points.size() == out_domain_samples);
            assert(w->out_of_domain.matrix.size() == out_domain_samples * num_vectors);
        }

        // 1. 挤压域内挑战
        auto [indices, points] = in_domain_challenges(prover_state);
        const ::whir::EngineId matrix_hash_id = matrix_commit_mt.layers.empty()
            ? ::whir::hash::ENGINE_ID_BLAKE3
            : matrix_commit_mt.layers.back().hash_id;

        // 多见证: 水平拼接求值子矩阵
        std::size_t n_witnesses = witnesses_list.size();
        std::size_t stride = n_witnesses * num_cols();
        std::vector<Source> matrix(indices.size() * stride, Source::zero());

        std::size_t col_offset = 0;
        for (const auto* w : witnesses_list) {
            // 2a. 提取被挑战的行到子矩阵
            std::vector<Source> submatrix;
            submatrix.reserve(indices.size() * num_cols());

            for (std::size_t pi = 0; pi < indices.size(); ++pi) {
                std::size_t row_start = indices[pi] * num_cols();
                for (std::size_t c = 0; c < num_cols(); ++c)
                    submatrix.push_back(w->matrix[row_start + c]);

                // 同时复制到水平拼接的输出矩阵
                for (std::size_t c = 0; c < num_cols(); ++c)
                    matrix[pi * stride + col_offset + c] = w->matrix[row_start + c];
            }

            // 将子矩阵作为提示发送（验证者用它重新计算叶子哈希）
            prover_state.prover_hint(submatrix);

            // 2b. Merkle 树打开 — 为被挑战的叶子发送兄弟哈希。
            bool opened_with_gpu_merkle_path = false;
#if defined(WHIR_CUDA) && defined(WHIR_CUDA_EXPERIMENTAL_NTT)
            if (matrix_hash_id == ::whir::hash::ENGINE_ID_SHA2 &&
                ::whir::cuda::gpu_dispatch_enabled() &&
                w->matrix_leaves.size() == codeword_length) {
                const auto hint_nodes = ::whir::cuda::merkle_hint_node_indices(
                    w->matrix_leaves.size(), std::span<const std::size_t>{indices});
                ::whir::hash::Hash root{};
                std::vector<::whir::hash::Hash> hints(hint_nodes.size());
                ::whir::cuda::gpu_sha256_merkle_open_path(
                    reinterpret_cast<const std::uint8_t*>(w->matrix_leaves.data()),
                    w->matrix_leaves.size(), std::span<const std::size_t>{indices},
                    root.data(), reinterpret_cast<std::uint8_t*>(hints.data()));
                for (const auto& h : hints) prover_state.prover_hint(h);
                opened_with_gpu_merkle_path = true;
            }
#endif
            if (!opened_with_gpu_merkle_path) {
                merkle_tree::open(prover_state, matrix_commit_mt,
                                  w->matrix_witness, std::span<const std::size_t>{indices});
            }

            col_offset += num_cols();
        }

        return {std::move(points), std::move(matrix)};
    }

    // =========================================================================
    // verify — 验证域内求值（验证者端）
    //
    // 对应 Rust: Config::verify()
    //
    // 对每个承诺:
    //   1. 接收子矩阵提示（证明者声明的被挑战行）
    //   2. 从子矩阵重新计算叶子哈希（commit_leaves）
    //   3. merkle_tree::verify -> 从叶子 + Merkle 路径重建根，比较
    //   4. 将子矩阵水平拼接到输出
    // =========================================================================
    template <typename Transcript>
    Evaluations<Source> verify(
        Transcript& verifier_state,
        std::span<const Commitment<Target>*> commitments_list) const
    {
        for (const auto* c : commitments_list) {
            assert(c->out_of_domain.points.size() == out_domain_samples);
            assert(c->out_of_domain.matrix.size() == num_vectors * out_domain_samples);
        }

        // 挤压与证明者相同的确定性挑战索引
        auto [indices, points] = in_domain_challenges(verifier_state);
        const ::whir::EngineId matrix_hash_id = matrix_commit_mt.layers.empty()
            ? ::whir::hash::ENGINE_ID_BLAKE3
            : matrix_commit_mt.layers.back().hash_id;

        std::size_t n_commitments = commitments_list.size();
        std::size_t stride = n_commitments * num_cols();
        std::vector<Source> matrix(indices.size() * stride, Source::zero());

        std::size_t col_offset = 0;
        for (const auto* c : commitments_list) {
            // 1. 从证明者接收子矩阵提示
            std::vector<Source> submatrix;
            if (!verifier_state.prover_hint(submatrix)) return {};

            // 2. 从接收到的子矩阵重新计算叶子哈希
            //    如果证明者篡改了行数据，重新计算的哈希将不匹配
            //    Merkle 路径 -> 验证失败。
            ::whir::hash::Blake3 blake3_engine;
            ::whir::hash::Sha2 sha2_engine;
            const ::whir::hash::HashEngine& verify_leaf_engine =
                (matrix_hash_id == ::whir::hash::ENGINE_ID_SHA2)
                    ? static_cast<const ::whir::hash::HashEngine&>(sha2_engine)
                    : static_cast<const ::whir::hash::HashEngine&>(blake3_engine);
            std::vector<::whir::hash::Hash> leaf_hashes(indices.size());
            ::whir::protocols::matrix_commit::commit_leaves<Source>(
                verify_leaf_engine, submatrix, num_cols(), leaf_hashes);

            // 3. Merkle 树验证 — 从叶子 + 路径提示重建根
            auto engine_lookup = [&blake3_engine, &sha2_engine](::whir::EngineId id) -> const ::whir::hash::HashEngine& {
                if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_engine;
                return blake3_engine;
            };

            if (!merkle_tree::verify(verifier_state, matrix_commit_mt,
                                     c->matrix_commitment,
                                     std::span<const std::size_t>{indices},
                                     std::span<const ::whir::hash::Hash>{leaf_hashes},
                                     engine_lookup)) {
                return {};  // Merkle 验证失败
            }

            // 4. 将子矩阵水平拼接到输出矩阵
            if (stride > 0 && num_cols() > 0) {
                for (std::size_t pi = 0; pi < indices.size(); ++pi) {
                    for (std::size_t c2 = 0; c2 < num_cols(); ++c2) {
                        matrix[pi * stride + col_offset + c2] =
                            submatrix[pi * num_cols() + c2];
                    }
                }
            }

            col_offset += num_cols();
        }

        return {std::move(points), std::move(matrix)};
    }
};

// ============================================================================
// num_in_domain_queries — 计算达到目标安全级别所需的域内查询次数
//
// 对应 Rust: irs_commit::num_in_domain_queries()
//
// 唯一解码:  delta = (1 + rho) / 2，每查询安全性 = -log2(delta)
// 列表解码:  delta = 1 - sqrt(rho) - eta，eta = sqrt(rho) / 20
//
// 所需查询数 q: q >= security_target / (-log2(per_sample))
// ============================================================================
inline double num_in_domain_queries(bool unique_decoding, double security_target, double rate) {
    double johnson_slack = unique_decoding ? 0.0 : std::sqrt(rate) / 20.0;

    // 每查询"错误概率"（作弊证明者未被检测到的概率）
    double per_sample = unique_decoding
        ? (1.0 + rate) / 2.0              // 唯一解码: delta = (1 + rho) / 2
        : std::sqrt(rate) + johnson_slack; // 列表解码: delta = sqrt(rho) + eta

    // q = ceil(security_target / -log2(per_sample))
    return std::ceil(security_target / (-std::log2(per_sample)));
}

} // namespace whir::protocols::irs_commit
