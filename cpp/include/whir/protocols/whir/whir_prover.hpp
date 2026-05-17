#pragma once

// =============================================================================
// whir_prover.hpp — WHIR 证明者完整实现。
// 对应 WHIR 中的 src/protocols/whir/prover.rs。
//
// 定义 Config<M>::prove() 模板成员函数 — 10 步 WHIR 证明流程。
//
// 此文件由 whir.hpp 在末尾 include, 不要单独 #include。
// =============================================================================

#include "../geometric_challenge.hpp"
#include "../../algebra/linear_form.hpp"
#include "../../algebra/multilinear.hpp"
#include "../../algebra/sumcheck.hpp"
#include "../../algebra/utilities.hpp"
#include "../../hash/blake3_engine.hpp"
#include "../../hash/sha2_engine.hpp"
#include "../../utils.hpp"

#include <cassert>
#include <deque>
#include <memory>
#include <span>
#include <vector>

namespace whir::protocols::whir {

// =============================================================================
// Config<M>::prove() — WHIR 完整证明 (10 步)。
//
// 输入:
//   prover_state  — ProverState (Fiat-Shamir transcript)
//   vectors_span  — 原始向量列表 (基域, 每个长度 = initial_size)
//   witnesses     — commit() 返回的 Witness 列表 (每个包含编码矩阵 + Merkle 见证 + 域外求值)
//   linear_forms  — 约束的线性形式 (unique_ptr 列表, 每个形式长度为 initial_size)
//   evaluations   — 声明的求值: eval[i * nvec + j] = linear_form[i](vector[j])
//
// 输出: FinalClaim<Target>
//       - evaluation_point: 所有 sumcheck 轮坐标的拼接
//       - rlc_coefficients: 初始约束 RLC 系数
//       - linear_form_rlc: F::zero() (prover 不需要计算, verifier 侧填入)
//
// 10 步流程:
//   1. 补全跨承诺的 OOD 评价值 (确保每个向量在每个域外点都有求值)
//   2. 向量的随机线性组合 (geometric challenge → vector_rlc)
//   3. 约束的随机线性组合 (geometric challenge → constraint_rlc + oods_rlc)
//   4. 计算 "The Sum" (vector RLC · evaluation RLC + OOD 约束)
//   5. 初始 sumcheck (验证初始声明 → 得到部分求值点)
//   6. 逐轮 WHIR:
//      a) IRS 承诺当前折叠向量
//      b) PoW (反 Grinding)
//      c) 打开前一轮 witness (首轮用 initial_committer, 后续用 prev_rc)
//      d) 收集 STIR 约束 (OOD + in-domain)
//      e) STIR sumcheck → 扩展求值点
//   7. 发送最终向量 (明文发送折叠后的系数)
//   8. 最终 PoW
//   9. 打开最终 witness (域内验证)
//  10. 最终 sumcheck → 补全求值点
// =============================================================================

template <typename M>
template <typename Transcript>
//生成一个最终证明
FinalClaim<typename M::Target> Config<M>::prove(
    Transcript& prover_state,
    std::span<const std::span<const Source>> vectors_span,
    std::span<const irs_commit::Witness<Source, Target>> witnesses, //witness包含了这些向量的初始承诺以及它们在域外点的求值
    std::vector<std::unique_ptr<::whir::algebra::LinearForm<Target>>> linear_forms,  //线性约束
    std::span<const Target> evaluations) const  //它们在向量上的公开评价值
{
    using F = Target;
    const std::size_t num_vectors = vectors_span.size();      // 多项式个数
    const std::size_t num_linear_forms = linear_forms.size();  // 约束个数

    // ---- 输入验证 ----
    
    //总向量数必须等于每个Witness负责的向量数*Witness数量
    assert(num_vectors == witnesses.size() * initial_committer.num_vectors);

    // evaluation大小是一个扁平化的矩阵:行数是约束的数量(num_linear_forms),列表是多项式数量(num_vectors)
    assert(evaluations.size() == num_vectors * num_linear_forms);
    for (const auto& v : vectors_span) assert(v.size() == initial_size());
    for (const auto& lf : linear_forms) assert(lf->size() == initial_size());
    if (num_vectors == 0) return FinalClaim<F>{};

    ::whir::hash::Blake3 blake3_pow_engine;
    ::whir::hash::Sha2 sha2_pow_engine;
    auto pow_engine_lookup =
        [&blake3_pow_engine, &sha2_pow_engine](::whir::EngineId id)
            -> const ::whir::hash::HashEngine& {
        if (id == ::whir::hash::ENGINE_ID_SHA2) return sha2_pow_engine;
        return blake3_pow_engine;
    };

    // ==========================================================================
    // 步骤 1: 补全跨承诺的 OOD (Out-Of-Domain) 评价值。
    //
    // 背景: 每个 witness 只包含"自己的向量"在域外点的求值,
    //       但 STIR 折叠需要"所有向量"在每个域外点的值。
    //       对不在当前 witness 中的向量, 额外计算并发送其 OOD 求值。
    //
    // 输入: witnesses[].out_of_domain — 每个 witness 的域外求值
    // 输出: oods_evals  — UnivariateEvaluation 列表 (用于后续 accumulate_many)
    //       oods_matrix — 完整的域外求值矩阵 (域外点数 × num_vectors, 行主序)
    // ==========================================================================
    std::vector<::whir::algebra::UnivariateEvaluation<F>> oods_evals;
    std::vector<F> oods_matrix;
    {
        std::size_t vector_offset = 0;
        for (const auto& witness : witnesses) {

            // 获取当前 witness 的域外求值器Univariation (每个域外点一个)
            auto w_evals = witness.out_of_domain.evaluators(initial_size());

            //num_columns=matrix.size/points.size
            std::size_t w_cols = witness.out_of_domain.num_columns();

            //witness的域外求值构造器,然后ei点的Univariation
            for (std::size_t ei = 0; ei < w_evals.size(); ++ei) {
                const auto& oods_eval = w_evals[ei];

                //遍历每一列
                for (std::size_t j = 0; j < num_vectors; ++j) {
                    
                    //如果向量j本来就是被当前Witness管理的,那么这个求值在之前生成Witness时就已经计算过了
                    //直接从witness.out_of_domain.matrix中读取并填入完整的oods_matrix中即可
                    if (j >= vector_offset && j < w_cols + vector_offset) {
                        // 当前 witness 包含此向量 → 直接取已有值
                        oods_matrix.push_back(
                            witness.out_of_domain.matrix[ei * w_cols + (j - vector_offset)]);
                    } else {
                        // 当前 witness 不包含此向量 → 额外计算并发送
                        // 使用嵌入映射 M 把基域向量 lift 到扩展域, 在域外点求值
                        F eval = oods_eval.evaluate(*embedding(), vectors_span[j]);
                        prover_state.prover_message(eval);
                        oods_matrix.push_back(eval);
                    }
                }
                oods_evals.push_back(oods_eval);
            }
            vector_offset += witness.num_vectors();
        }
    }

    /*例子:
     witness[0]:                        witness[1]:
      covers v0, v1                      covers v2, v3
      OOD point = α₀                     OOD point = α₁
      OOD matrix = [v0(α₀), v1(α₀)]     OOD matrix = [v2(α₁), v3(α₁)]

    逐行执行

    外层循环 — 遍历 witness[0]（vector_offset=0, w_cols=2）：

    ei=0: oods_eval = witness[0] 在 α₀ 处的求值器

      j=0: v0 → 在范围内 (0 >= 0 && 0 < 2) → 直接用已有值 v0(α₀)
      j=1: v1 → 在范围内 (1 >= 0 && 1 < 2) → 直接用已有值 v1(α₀)
      j=2: v2 → 不在范围内 → oods_eval.evaluate(embedding, v2) = v2(α₀) → 发给验证者
      j=3: v3 → 不在范围内 → oods_eval.evaluate(embedding, v3) = v3(α₀) → 发给验证者

      oods_matrix 追加列: [v0(α₀), v1(α₀), v2(α₀), v3(α₀)]  ✓ 完整了

    外层循环 — 遍历 witness[1]（vector_offset=2, w_cols=2）：

    ei=0: oods_eval = witness[1] 在 α₁ 处的求值器

      j=0: v0 → 不在范围内 (0 < 2) → 计算 v0(α₁) → 发给验证者
      j=1: v1 → 不在范围内 (1 < 2) → 计算 v1(α₁) → 发给验证者
      j=2: v2 → 在范围内 (2 >= 2 && 2 < 4) → 直接用已有值 v2(α₁)
      j=3: v3 → 在范围内 (3 >= 2 && 3 < 4) → 直接用已有值 v3(α₁)

      oods_matrix 追加列: [v0(α₁), v1(α₁), v2(α₁), v3(α₁)]  ✓ 完整了

    最终输出

    oods_matrix (2 行 × 4 列, 行主序):
      行0: v0(α₀)  v1(α₀)  v2(α₀)  v3(α₀)     ← 所有向量在 α₀ 的值
      行1: v0(α₁)  v1(α₁)  v2(α₁)  v3(α₁)     ← 所有向量在 α₁ 的值

    oods_evals: [α₀求值器, α₁求值器]            ← 域外点的求值器，后续步骤复用
    */


    // ==========================================================================
    // 步骤 2: 向量的随机线性组合 (Vector RLC)。
    //
    // geometric_challenge 从 transcript 挤出等比数列:
    //   chall[0]=1, chall[i+1] = chall[i] * alpha  (alpha 是 transcript 挤出的随机数)
    //
    // 折叠: vector = Σ vector_rlc_coeffs[i] * vectors[i]
    //       注意 vector_rlc_coeffs[0] == 1 (geometric_challenge 保证首元素为 1)
    //
    // 输出: vector_rlc_coeffs — 长度为 num_vectors 的等比数列
    //       vector            — 折叠后的单一向量 (长度 = initial_size)
    // ==========================================================================

    // 从trascript中读取一个随机元素r,生成一个几何序列[1,r,r^2,...r^num_vectors-1]
    auto vector_rlc_coeffs = geometric_challenge<F>(prover_state, num_vectors);
    assert(vector_rlc_coeffs[0] == F::one());

    // 取出第一个向量
    std::vector<F> vector = ::whir::algebra::lift<M>(*embedding(), vectors_span[0]);
    
    //通过lift操作将基域上的V0提升映射到扩展域上,并将其作为累加器vector的初始值。
    for (std::size_t i = 1; i < num_vectors; ++i)
        //V_acc<-V_acc+r^i*V_i
        ::whir::algebra::mixed_scalar_mul_add<M>(*embedding(), vector, vector_rlc_coeffs[i], vectors_span[i]);


    /*
    举例:假设r=2
    i=0,vector=1*v0=[3,5,1,2]
    i=1,vector=vector+2*lift(v1), vector = [3, 5, 1, 2] + 2·[7, 0, 4, 9]= [3, 5, 1, 2] + [14, 0, 8, 18]= [17, 5, 9, 20]
    ...
    i=2:vector=vector+4*lift(v2),vector = [17, 5, 9, 20] + 4·[2, 8, 6, 1]= [17, 5, 9, 20] + [8, 32, 24, 4]= [25, 37, 33, 24]
    */




    // ==========================================================================
    // 步骤 3: 约束的随机线性组合 (Constraint RLC)。
    //
    // 对 num_linear_forms 个约束 + oods_evals.size() 个域外约束做 RLC。
    // 结果分成两段:
    //   initial_forms_rlc[0..num_linear_forms) — 初始约束的 RLC 系数
    //   oods_rlc[0..oods_evals.size())         — 域外约束的 RLC 系数
    //
    // 输出: constraint_rlc_coeffs — 长度 = num_linear_forms + oods_evals.size()
    //       initial_forms_rlc     — 约束 RLC 系数 (span 视图)
    //       oods_rlc              — 域外 RLC 系数 (span 视图)
    //       covector              — 累积的线性形式 covector (长度 = initial_size)
    // ==========================================================================
    
    //从prover_state中抽取了一个随机因子beta,生成几何数组[1,beta,beta^2,...,beta^n-1]
    auto constraint_rlc_coeffs = geometric_challenge<F>(prover_state,
        num_linear_forms + oods_evals.size());

    bool has_constraints = !constraint_rlc_coeffs.empty();
    
    //前半部分长度为num_linear_forms,分配给常规约束
    std::span<const F> initial_forms_rlc(constraint_rlc_coeffs.data(), num_linear_forms);
    
    //后半部分分配个OOD求值约束
    std::span<const F> oods_rlc(std::span{constraint_rlc_coeffs}.subspan(num_linear_forms));

    // 构建 covector: 即 Σ constraint_rlc[i] * linear_form[i] 的系数表示
    std::vector<F> covector;
    if (num_linear_forms > 0) { //如果有约束->累加所有线性形式
        covector.resize(initial_size(), F::zero());

        //linear_forms是一个LinearForm的vector
        linear_forms[0]->accumulate(covector, F::one());
        

        //遍历linear_forms(记为Li),covector=1*L0+beta*L1+beta^2*L2+...
        for (std::size_t i = 1; i < num_linear_forms; ++i)
            linear_forms[i]->accumulate(covector, constraint_rlc_coeffs[i]);

    } else if (has_constraints) {  //没有线性形式但有OOD->仍然分配零covector
        covector.resize(initial_size(), F::zero());
    }


    // ==========================================================================
    // 步骤 4: 计算 "The Sum" — sumcheck 的目标值。
    //
    // the_sum = Σ_i constraint_rlc[i] * (Σ_j vector_rlc[j] * eval[i][j])
    //          + Σ_i oods_rlc[i]   * (Σ_j vector_rlc[j] * ood_matrix[i][j])
    //
    // 直观理解:
    //   - 对每个约束 i: 把该约束下所有向量的求值做 vector RLC
    //   - 把所有约束的 vector RLC 结果再做 constraint RLC
    //   - 加上域外约束的贡献
    //
    // 输出: the_sum — 一个扩展域标量, 作为初始 sumcheck 的 target
    // ==========================================================================
    F the_sum = F::zero();

    // 初始约束部分
    for (std::size_t i = 0; i < num_linear_forms; ++i) {
        F row_sum = F::zero();

        //1.先按行(固定约束i,遍历多项式j)折叠多项式的求值
        for (std::size_t j = 0; j < num_vectors; ++j)
            
            //假设我们有矩阵E,E_ij=evaluations[i*num_vectors+j],
            //代表第i个约束对第j个多项式的求值E_ij=L_i(V_j)
            row_sum += vector_rlc_coeffs[j] * evaluations[i * num_vectors + j];
        
        //2.再按列(遍历约束i)折叠这些求值总和
        the_sum += constraint_rlc_coeffs[i] * row_sum;
        
        //L_batch(V_batch)=sum_i (beta^i *L_i) sum_j(r^j*V_j)
        //the_sum=sum_i beta^i(sum_j r^j*L_i(V_j))
    }

    // 域外约束部分: 先把 OOD 约束累积到 全局covector
    ::whir::algebra::UnivariateEvaluation<F>::accumulate_many(oods_evals, covector, oods_rlc);
    
    for (std::size_t i = 0; i < oods_rlc.size(); ++i) {
        F row_sum = F::zero();

        //同样双重折叠,只是数据源换成了oods_matrix
        //evaluations:num_linear_forms行*num_vectors列
        //evaluations[i][j]=第i个线性约束在向量v_j上求值
        //ood_matrix: oods_evals.size()行*num_vectors列
        //ood_matrix[k][j]=向量v_j在第k个域外点a_k上的求值,即v_j(a_k)
        for (std::size_t j = 0; j < num_vectors; ++j)
            row_sum += vector_rlc_coeffs[j] * oods_matrix[i * num_vectors + j];
        the_sum += oods_rlc[i] * row_sum;
    }

    // ==========================================================================
    // 步骤 5: 初始 sumcheck。
    //
    // 验证声明: ⟨vector, covector⟩ = the_sum
    //
    // 如有约束 (has_constraints=true):
    //   → 运行 sumcheck 协议, 得到 num_rounds 个折叠坐标
    //
    // 如无约束 (has_constraints=false):
    //   → verifier 直接挤出随机折叠坐标
    //   → 执行跳过 PoW (占位, 维持 transcript 一致性)
    //   → 手动折叠 vector
    //
    // 输出: evaluation_point — 初始折叠坐标 (length = num_rounds)
    //       vector          — 折叠后的向量 (长度减半)
    //       covector        — 折叠后的 covector
    // ==========================================================================
    std::vector<F> evaluation_point;
    bool is_first_round = true;

    if (has_constraints) { //有约束
        // 正常运行 sumcheck: prove → 返回 coordinates
        auto fr = initial_sumcheck.prove(prover_state, vector, covector, the_sum);
        evaluation_point = std::move(fr.coords); //Multilinear多项式中的randomness值坐标
    } else {
        // 无约束路径: verifier 挤出坐标, 手动折叠
        auto fr = prover_state.template verifier_message_vec<F>(initial_sumcheck.num_rounds);
        // 运行跳过 PoW (维持 transcript 同步)
        initial_skip_pow.prove(prover_state, pow_engine_lookup);
        // 用挤出坐标折叠 vector
        for (auto& f : fr) ::whir::algebra::fold<F>(vector, f);
        covector.assign(initial_sumcheck.final_size(), F::zero());
        evaluation_point = std::move(fr);
    }

    // ==========================================================================
    // 步骤 6: 逐轮 WHIR (STIR — Sumcheck + Tensor + Interleaved RS)。
    //
    // 每轮的数据流:
    //   6a. IRS 承诺当前折叠向量 → new_witness
    //   6b. PoW (找 nonce 满足难度)
    //   6c. 打开前一轮的 witness (域内挑战 + Merkle 路径)
    //       - 首轮: 用 initial_committer 打开多个原始 witness → lift 到扩域
    //       - 后续: 用 prev_rc.irs_committer 打开单个 prev_witness
    //   6d. 收集 STIR 约束:
    //       - 域外约束 (来自 new_witness 的 OOD 求值)
    //       - 域内约束 (来自打开的前轮 in-domain 求值)
    //       - 域内值权重 = tensor_product(vector_rlc, eq_weights)
    //   6e. STIR sumcheck → 扩展 evaluation_point
    //
    // 折叠效果: 每轮 vector 长度减半 (变量数减 1)
    //          evaluation_point 长度增加 sumcheck.num_rounds
    // ==========================================================================
    const irs_commit::Witness<F, F>* prev_round_witness = nullptr;

    // 持久化所有 round 的 witness, 避免悬空指针。
    // Rust 侧通过 RoundWitness enum 持有所有权, C++ 用 deque 保证指针稳定。
    std::deque<irs_commit::Witness<F, F>> stored_round_witnesses; //双端队列

    // 上一轮 sumcheck 的折叠随机性 (用于步骤 6d eq_weights), 初始为 initial sumcheck 的结果。
    // Rust: folding_randomness.eq_weights() — 每轮只用最近一轮的随机性, 不用累积坐标。
    //记录上一层Sumcheck吐出的随机坐标点(即折叠随机数)。初始状态下等于最外层初始Sumcheck生成的坐标.
    std::vector<F> last_fr_coords = evaluation_point;


    //开始遍历所有配置好的折叠轮次,每一轮会使多项式的变量数减少，多项式长度指数级缩小
    for (std::size_t round_idx = 0; round_idx < round_configs.size(); ++round_idx) {
        const auto& rc = round_configs[round_idx];

        // --- 6a. IRS 承诺当前折叠向量 ---
        // 把长度为 initial_size 的 vector 包装为单向量 span 交给 IRS commit
        std::span<const F> vec_single{vector};
        std::vector<std::span<const F>> single_span{vec_single};

        //irs_commiter.commit输出Witness{matrix, matrix_witness, out_of_domain}
        auto new_witness = rc.irs_committer.commit(prover_state, single_span);
        // new_witness 包含: RS 编码矩阵 + Merkle 树 + 域外采样 + 域外求值

        // --- 6b. PoW (反 Grinding 攻击) ---
        rc.pow.prove(prover_state, pow_engine_lookup);

        // --- 6c. 打开前一轮 witness (域内挑战) ---
        irs_commit::Evaluations<F> in_domain;
        if (is_first_round) {
            // 首轮: 打开 initial_committer 的多个 witness, 然后 lift 到扩域
            std::vector<const irs_commit::Witness<Source, Target>*> wptrs;
            wptrs.reserve(witnesses.size());
            for (const auto& w : witnesses) wptrs.push_back(&w);
            auto in_domain_src = initial_committer.open(prover_state, wptrs);
            in_domain = in_domain_src.template lift<M>(*embedding());
            is_first_round = false;
        } else {
            // 后续轮: 打开上一轮的单个 witness
            auto& prev_rc = round_configs[round_idx - 1];
            std::vector<const irs_commit::Witness<F, F>*> wptrs{prev_round_witness};
            in_domain = prev_rc.irs_committer.open(prover_state, wptrs);
        }
        // in_domain.points  = 域内挑战点
        // in_domain.matrix  = 被挑战行的子矩阵

        // --- 6d. 收集 STIR 约束 ---
        // STIR 约束 = 域外约束 + 域内约束
        auto stir_challenges = new_witness.out_of_domain.evaluators(rc.sumcheck.initial_size);
        auto in_domain_evals = in_domain.evaluators(rc.sumcheck.initial_size);
        stir_challenges.insert(stir_challenges.end(), in_domain_evals.begin(), in_domain_evals.end());

        // STIR 评价值: OOD values (权重 = [1]) + in-domain values (权重 = tensor_product)
        F one_val = F::one();
        auto stir_evaluations = new_witness.out_of_domain.values(std::span<const F>{&one_val, 1});

        // tensor_product(rlc_coeffs, eq_weights): 把 RLC 系数和 eq 权重张量积
        // eq_weights(r) = Π r_i^(1 - b_i) * (1 - r_i)^b_i   (多线性基)
        // 关键: 只用上一轮的折叠随机性 (last_fr_coords), 不用累积的 evaluation_point。
        // Rust: folding_randomness.eq_weights()
        auto eq_w = last_fr_coords.empty()
            ? std::vector<F>{F::one()}
            : ::whir::algebra::MultilinearPoint<F>(last_fr_coords).eq_weights();
        auto tp = ::whir::algebra::tensor_product<F>(vector_rlc_coeffs, eq_w);
        auto in_domain_vals = in_domain.values(tp);
        stir_evaluations.insert(stir_evaluations.end(), in_domain_vals.begin(), in_domain_vals.end());

        // STIR RLC: 把 STIR 约束做随机线性组合
        auto stir_rlc = geometric_challenge<F>(prover_state, stir_challenges.size());
        ::whir::algebra::UnivariateEvaluation<F>::accumulate_many(stir_challenges, covector, stir_rlc);
        the_sum += ::whir::algebra::dot<F>(stir_rlc, stir_evaluations);

        // --- 6e. STIR sumcheck ---
        // 验证 ⟨vector, covector⟩ = the_sum (在折叠后的域上)
        auto fr = rc.sumcheck.prove(prover_state, vector, covector, the_sum);
        evaluation_point.insert(evaluation_point.end(), fr.coords.begin(), fr.coords.end());
        last_fr_coords = std::move(fr.coords);  // 更新为当前轮的折叠随机性, 供下一轮步骤 6d 使用

        // 更新状态为下一轮
        vector_rlc_coeffs = {F::one()};  // 下一轮的 RLC 只有单个向量

        // 持久化 new_witness — 每轮都存, 下一轮 open (步骤 6c) 和最终 open (步骤 9) 都需要
        stored_round_witnesses.push_back(std::move(new_witness));
        prev_round_witness = &stored_round_witnesses.back();
    }

    // ==========================================================================
    // 步骤 7: 发送最终向量。
    //
    // 此时 vector 已折叠到 final_size, 明文发送所有系数给 verifier。
    // verifier 需要用这些系数验证最终 sumcheck 的一致性。
    //
    // 输入: vector (长度 = final_sumcheck.initial_size)
    // 输出: 通过 transcript 逐元素发送
    // ==========================================================================
    assert(vector.size() == final_sumcheck.initial_size);
    for (const auto& coeff : vector)
        prover_state.prover_message(coeff);

    // ==========================================================================
    // 步骤 8: 最终 PoW。
    // 输入: pow_engine_lookup — 配置选择的哈希引擎
    // 输出: 通过 transcript 发送 nonce
    // ==========================================================================
    {
        final_pow.prove(prover_state, pow_engine_lookup);
    }

    // ==========================================================================
    // 步骤 9: 打开最终 witness (域内验证)。
    //
    // 如果是首轮 (从未进入主循环): 打开 initial_committer 的多个原始 witness
    // 否则: 打开最后一轮的 witness
    //
    // 输入: prev_round_witness 或 witnesses[]
    // 输出: 通过 transcript 发送子矩阵 + Merkle 路径 hints
    // ==========================================================================
    if (is_first_round) {
        std::vector<const irs_commit::Witness<Source, Target>*> wptrs;
        for (const auto& w : witnesses) wptrs.push_back(&w);
        initial_committer.open(prover_state, wptrs);
    } else if (prev_round_witness) {
        auto& prev_rc = round_configs.back();
        std::vector<const irs_commit::Witness<F, F>*> wptrs{prev_round_witness};
        prev_rc.irs_committer.open(prover_state, wptrs);
    }

    // ==========================================================================
    // 步骤 10: 最终 sumcheck。
    //
    // 验证最后一轮折叠后 ⟨vector, covector⟩ = the_sum
    // 返回的结果中的 coords 追加到 evaluation_point 末尾。
    //
    // 输入: vector (已折叠到 final_sumcheck.initial_size)
    //       covector
    //       the_sum
    // 输出: final_fr.coords — 最终折叠坐标, 追加到 evaluation_point
    // ==========================================================================
    auto final_fr = final_sumcheck.prove(prover_state, vector, covector, the_sum);
    evaluation_point.insert(evaluation_point.end(), final_fr.coords.begin(), final_fr.coords.end());

    // 返回 FinalClaim (linear_form_rlc 由 verifier 端计算)
    return FinalClaim<F>{
        std::move(evaluation_point),
        std::vector<F>(initial_forms_rlc.begin(), initial_forms_rlc.end()),
        F::zero(),
    };
}

} // namespace whir::protocols::whir
