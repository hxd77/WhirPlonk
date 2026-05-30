// ===========================================================================
// dump_algebra_utils.cpp — 代数工具 + 多线性 + sumcheck + 线性形式 golden test。
//
// 运行: ./dump_algebra_utils > golden_algebra_cpp.txt
// 对拍: diff <(tr -d '\r' < golden_algebra_rs.txt) golden_algebra_cpp.txt
//
// 覆盖 5 个 SECTION, 每个用独立 LCG 种子:
//   1. utilities     — 几何序列、内积、张量积、单变量求值、标量乘加、几何累加
//   2. multilinear   — 多线性扩张求值 (MLE) + 相等多项式 (eval_eq)
//   3. sumcheck      — sumcheck 多项式计算 (c0/c2) + fold 折叠
//   4. linear_form   — Covector / MultilinearExtension / UnivariateEvaluation
//   5. utils         — base_decomposition + expand_randomness
//
// 对应 Rust: examples/dump_algebra.rs
// ===========================================================================

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/linear_form.hpp"
#include "whir/algebra/multilinear.hpp"
#include "whir/algebra/sumcheck.hpp"
#include "whir/algebra/utilities.hpp"
#include "whir/utils.hpp"
#include <cstdint>
#include <cstdio>
#include <vector>

using whir::algebra::Goldilocks;

// ===========================================================================
// LCG — 线性同余生成器 (与 Rust 侧完全一致)
// 公式: X_{n+1} = (6364136223846793005 * X_n + 1442695040888963407) mod 2^64
// ===========================================================================
struct Lcg { uint64_t s; explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

/// 打印 Goldilocks 元素: "  <label> <u64值>"
static void print_base(const char* label, Goldilocks a) {
    std::printf("%s %llu\n", label, (unsigned long long)a.as_canonical_u64());
}

int main() {
    // 向量打印 lambda: 输出长度 + 每个元素一行 (5 空格缩进)
    auto dump_base_vec = [](const char* label, const std::vector<Goldilocks>& v) {
        std::printf("  %s %zu\n", label, v.size());
        for (const auto& x : v) std::printf("     %llu\n", (unsigned long long)x.as_canonical_u64());
    };

    // ========================================================================
    // SECTION utilities — 代数工具函数 (seed: 0x1111...)
    //
    // 6 个 CASE, 覆盖 WHIR 中最常用的代数辅助函数:
    //   CASE 0: geometric_sequence(base, 8) → [1, base, base², ..., base⁷]
    //           用于 WHIR 协议中从单个挑战值展开多个随机值
    //   CASE 1: dot(a[8], b[8]) → sum_i a[i]*b[i]
    //           计算两个向量的内积
    //   CASE 2: tensor_product(a[3], b[2]) → 6 个元素
    //           c[i*|b|+j] = a[i]*b[j], 用于组合多个权重向量
    //   CASE 3: univariate_evaluate(coeffs[8], x)
    //           Horner 法单变量多项式求值: coeffs[0] + coeffs[1]*x + ...
    //   CASE 4: scalar_mul_add(acc, w, vec) — 原地 acc[i] += w * vec[i]
    //   CASE 5: geometric_accumulate(acc[8], scalars[3], points[3])
    //           原地 acc[i] += sum_j scalars[j] * points[j]^i
    //           用于 WHIR 中 OOD 约束的批量累加
    //
    // 对应 C++: algebra/utilities.hpp
    // ========================================================================
    std::printf("# SECTION utilities\n");
    {   Lcg rng(0x1111111111111111ULL);

        // CASE 0: geometric_sequence — 几何序列 [1, x, x², ..., x⁷]
        Goldilocks base = Goldilocks::from_u64(rng.next());
        std::printf("CASE 0 geometric_sequence\n");
        dump_base_vec("seq", whir::algebra::geometric_sequence<Goldilocks>(base, 8));

        // CASE 1: dot — 内积
        std::vector<Goldilocks> a, b;
        for (int i = 0; i < 8; ++i) a.push_back(Goldilocks::from_u64(rng.next()));
        for (int i = 0; i < 8; ++i) b.push_back(Goldilocks::from_u64(rng.next()));
        std::printf("CASE 1 dot\n");
        print_base("  result", whir::algebra::dot<Goldilocks>(
            std::span<const Goldilocks>{a}, std::span<const Goldilocks>{b}));

        // CASE 2: tensor_product — 张量积
        std::vector<Goldilocks> aa, bb;
        for (int i = 0; i < 3; ++i) aa.push_back(Goldilocks::from_u64(rng.next()));
        for (int i = 0; i < 2; ++i) bb.push_back(Goldilocks::from_u64(rng.next()));
        std::printf("CASE 2 tensor_product\n");
        dump_base_vec("tp", whir::algebra::tensor_product<Goldilocks>(
            std::span<const Goldilocks>{aa}, std::span<const Goldilocks>{bb}));

        // CASE 3: univariate_evaluate — 单变量多项式求值(霍纳法则)
        std::vector<Goldilocks> coeffs;
        for (int i = 0; i < 8; ++i) coeffs.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks x = Goldilocks::from_u64(rng.next());
        std::printf("CASE 3 univariate_evaluate\n");
        print_base("  result", whir::algebra::univariate_evaluate<Goldilocks>(
            std::span<const Goldilocks>{coeffs}, x));

        // CASE 4: scalar_mul_add — 标量乘加
        std::vector<Goldilocks> acc;
        for (int i = 0; i < 8; ++i) acc.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks w = Goldilocks::from_u64(rng.next());
        std::vector<Goldilocks> vec_in;
        for (int i = 0; i < 8; ++i) vec_in.push_back(Goldilocks::from_u64(rng.next()));
        whir::algebra::scalar_mul_add<Goldilocks>(
            std::span<Goldilocks>{acc}, w, std::span<const Goldilocks>{vec_in});
        std::printf("CASE 4 scalar_mul_add\n"); dump_base_vec("acc", acc);

        // CASE 5: geometric_accumulate — 几何累加
        std::vector<Goldilocks> acc2;
        for (int i = 0; i < 8; ++i) acc2.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<Goldilocks> scalars, points;
        for (int i = 0; i < 3; ++i) scalars.push_back(Goldilocks::from_u64(rng.next()));
        for (int i = 0; i < 3; ++i) points.push_back(Goldilocks::from_u64(rng.next()));
        whir::algebra::geometric_accumulate<Goldilocks>(
            std::span<Goldilocks>{acc2}, std::move(scalars),
            std::span<const Goldilocks>{points});
        std::printf("CASE 5 geometric_accumulate\n"); dump_base_vec("acc", acc2);
    } //accumulator=scalar相加,然后scalars[i]=scalars[i]*point[i]

    // ========================================================================
    // SECTION multilinear — 多线性多项式 (seed: 0x2222...)
    //
    // multilinear_extend(evals, point):
    //   输入 evals 是布尔超立方上 2^k 个点的取值 (长度 n=2^k)
    //   输入 point 是求值点坐标 (k 个变量)
    //   用递归降维法 O(n) 时间求 MLE 在 point 处的值
    //
    // eval_eq(acc, point, scalar):
    //   原地 acc[i] += scalar * eq(point, i)
    //   其中 eq 是相等多项式: 当二进制展开 i == point 时为 1, 否则为 0
    //   用于 WHIR 中把求值约束编码为多项式恒等式
    //
    // 对应 C++: algebra/multilinear.hpp
    // ========================================================================
    std::printf("\n# SECTION multilinear\n");
    {   Lcg rng(0x2222222222222222ULL);
        int case_idx = 0;

        // CASE 0/1/2: multilinear_extend, k=3 (8个值), k=4 (16个值), k=5 (32个值)
        for (int k : {3, 4, 5}) {
            const std::size_t n = std::size_t{1} << k;
            std::vector<Goldilocks> evals, point;
            for (std::size_t i = 0; i < n; ++i) evals.push_back(Goldilocks::from_u64(rng.next()));
            for (int i = 0; i < k; ++i) point.push_back(Goldilocks::from_u64(rng.next()));
            std::printf("CASE %d multilinear_extend k=%d\n", case_idx++, k);
            print_base("  result", whir::algebra::multilinear_extend<Goldilocks>(
                std::span<const Goldilocks>{evals}, std::span<const Goldilocks>{point}));
        }

        // CASE 3: eval_eq, point 大小 3 → 输出 2^3=8 个值
        std::vector<Goldilocks> pt3;
        for (int i = 0; i < 3; ++i) pt3.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks s3 = Goldilocks::from_u64(rng.next());
        std::vector<Goldilocks> a3(8, Goldilocks::zero()); //2^3
        whir::algebra::eval_eq<Goldilocks>(
            std::span<Goldilocks>{a3}, std::span<const Goldilocks>{pt3}, s3);
        std::printf("CASE 3 eval_eq k=3\n"); dump_base_vec("acc", a3);

        // CASE 4: eval_eq, point 大小 4 → 输出 2^4=16 个值
        std::vector<Goldilocks> pt4;
        for (int i = 0; i < 4; ++i) pt4.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks s4 = Goldilocks::from_u64(rng.next());
        std::vector<Goldilocks> a4(16, Goldilocks::zero()); //2^4
        whir::algebra::eval_eq<Goldilocks>(
            std::span<Goldilocks>{a4}, std::span<const Goldilocks>{pt4}, s4);
        std::printf("CASE 4 eval_eq k=4\n"); dump_base_vec("acc", a4);
    }

    // ========================================================================
    // SECTION sumcheck — Sumcheck 协议底层 (seed: 0x3333...)
    //
    // compute_sumcheck_polynomial(a, b):
    //   给定两个等长向量 a, b, 计算 sumcheck 多项式系数:
    //     c0 = Σ a[2i] * b[2i+1]    (奇偶交叉项)
    //     c2 = Σ a[2i+1] * b[2i]    (偶奇交叉项)
    //     c1 = Σ a[i]*b[i] - 2*c0 - c2  (由调用方推导, 这里不算)
    //
    // fold(values, weight):
    //   用折叠随机性把 2n 个值压缩为 n 个:
    //     values'[i] = values[2i] + weight * (values[2i+1] - values[2i])
    //   这是 sumcheck 协议的核心归约: 把内积等式从 n 个变量压缩到 n-1 个
    //
    // 对应 C++: algebra/sumcheck.hpp
    // ========================================================================
    std::printf("\n# SECTION sumcheck\n");
    {   Lcg rng(0x3333333333333333ULL);
        int case_idx = 0;

        // CASE 0/1: compute_sumcheck_polynomial, n=8 和 n=16
        for (std::size_t n : {std::size_t{8}, std::size_t{16}}) {
            std::vector<Goldilocks> a, b;
            for (std::size_t i = 0; i < n; ++i) a.push_back(Goldilocks::from_u64(rng.next()));
            for (std::size_t i = 0; i < n; ++i) b.push_back(Goldilocks::from_u64(rng.next()));
            auto [acc0, acc2] = whir::algebra::compute_sumcheck_polynomial<Goldilocks>(
                std::span<const Goldilocks>{a}, std::span<const Goldilocks>{b});
            std::printf("CASE %d compute_sumcheck_polynomial n=%zu\n", case_idx++, n);
            print_base("  acc0", acc0);  // c0 系数
            print_base("  acc2", acc2);  // c2 系数
        }

        // CASE 2: fold — 16 个值折叠为 8 个值
        std::vector<Goldilocks> vals;
        for (int i = 0; i < 16; ++i) vals.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks wt = Goldilocks::from_u64(rng.next());
        whir::algebra::fold<Goldilocks>(vals, wt);
        std::printf("CASE 2 fold n=16\n"); dump_base_vec("folded", vals);
    }

    // ========================================================================
    // SECTION linear_form — 线性形式 (seed: 0x7777...)
    //
    // LinearForm<F> 是 WHIR 中表达"线性约束"的抽象基类, 三个具体实现:
    //
    //   Covector<F> — 显式向量 w, 线性泛函 ⟨w, v⟩
    //     - mle_evaluate(point): 对 w 做 MLE 求值
    //     - accumulate(acc, s):  acc[i] += s * w[i]
    //
    //   MultilinearExtension<F> — 固定点 p 处的相等多项式 eq(p, ·)
    //     - mle_evaluate(point): 计算 eq(p, point)
    //     - accumulate(acc, s):  acc[i] += s * eq(p, i)
    //
    //   UnivariateEvaluation<F> — 在点 x 处的单变量多项式求值
    //     - mle_evaluate(point): 张量积展开后求 MLE 值
    //     - accumulate(acc, s):  acc[i] += s * x^i
    //     - accumulate_many():   批量版, 用 geometric_accumulate 加速
    //
    // 对应 C++: algebra/linear_form.hpp
    // ========================================================================
    std::printf("\n# SECTION linear_form\n");
    {   using whir::algebra::Covector;
        using whir::algebra::MultilinearExtension;
        using whir::algebra::UnivariateEvaluation;
        Lcg rng(0x7777777777777777ULL);

        // --- CASE 0: Covector ---
        // 显式向量线性泛函, 长度 8 (k=3 个变量)
        std::vector<Goldilocks> cv_vec;
        for (int i = 0; i < 8; ++i) cv_vec.push_back(Goldilocks::from_u64(rng.next()));
        Covector<Goldilocks> cv{std::move(cv_vec)};
        std::vector<Goldilocks> pt3;
        for (int i = 0; i < 3; ++i) pt3.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks sc = Goldilocks::from_u64(rng.next());
        std::printf("CASE 0 covector\n");
        // size() 返回 2^k = 8
        print_base("  size", Goldilocks::from_u64(static_cast<uint64_t>(cv.size())));
        print_base("  mle_evaluate", cv.mle_evaluate(std::span<const Goldilocks>{pt3}));
        std::vector<Goldilocks> acc(8, Goldilocks::zero());
        cv.accumulate(std::span<Goldilocks>{acc}, sc);
        dump_base_vec("accumulate", acc);

        // --- CASE 1: MultilinearExtension ---
        // 相等多项式 eq(p, ·), point 大小 3
        std::vector<Goldilocks> mle_pt;
        for (int i = 0; i < 3; ++i) mle_pt.push_back(Goldilocks::from_u64(rng.next()));
        MultilinearExtension<Goldilocks> mle{std::move(mle_pt)};
        std::vector<Goldilocks> pt3b;
        for (int i = 0; i < 3; ++i) pt3b.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks sc2 = Goldilocks::from_u64(rng.next());
        std::printf("CASE 1 multilinear_extension\n");
        print_base("  size", Goldilocks::from_u64(static_cast<uint64_t>(mle.size())));
        print_base("  mle_evaluate", mle.mle_evaluate(std::span<const Goldilocks>{pt3b}));
        std::vector<Goldilocks> acc1(8, Goldilocks::zero());
        mle.accumulate(std::span<Goldilocks>{acc1}, sc2);
        dump_base_vec("accumulate", acc1);

        // --- CASE 2: UnivariateEvaluation ---
        // 单变量多项式求值泛函, 在点 x 处, size=8
        Goldilocks x = Goldilocks::from_u64(rng.next());
        UnivariateEvaluation<Goldilocks> ue{x, 8};
        std::vector<Goldilocks> pt3c;
        for (int i = 0; i < 3; ++i) pt3c.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks sc3 = Goldilocks::from_u64(rng.next());
        std::printf("CASE 2 univariate_evaluation\n");
        print_base("  size", Goldilocks::from_u64(static_cast<uint64_t>(ue.size())));
        print_base("  mle_evaluate", ue.mle_evaluate(std::span<const Goldilocks>{pt3c}));
        std::vector<Goldilocks> acc2(8, Goldilocks::zero());
        ue.accumulate(std::span<Goldilocks>{acc2}, sc3);
        dump_base_vec("accumulate", acc2);

        // --- CASE 3: accumulate_many ---
        // 3 个不同求值点的 UnivariateEvaluation, 批量累加到同一个 acc[8]
        std::vector<UnivariateEvaluation<Goldilocks>> evals;
        for (int i = 0; i < 3; ++i)
            evals.emplace_back(Goldilocks::from_u64(rng.next()), 8);
        std::vector<Goldilocks> scalars3;
        for (int i = 0; i < 3; ++i) scalars3.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<Goldilocks> acc3(8, Goldilocks::zero());
        UnivariateEvaluation<Goldilocks>::accumulate_many(
            evals, std::span<Goldilocks>{acc3}, std::span<const Goldilocks>{scalars3});
        std::printf("CASE 3 univariate_accumulate_many\n"); dump_base_vec("acc", acc3);
    }

    // ========================================================================
    // SECTION utils — 通用工具 (seed: 0x9999...)
    //
    // base_decomposition(value, base, n_bits):
    //   把 value 按 base 进制分解为 n_bits 个数字 (固定用例, 不依赖随机)
    //
    // expand_randomness(base, length):
    //   等价于 geometric_sequence — [1, base, base², ...], 共 length 项
    //
    // 对应 C++: utils.hpp
    // ========================================================================
    std::printf("\n # SECTION utils\n");
    {   // 固定测试用例: (值, 进制, 位数)
        struct Case { std::size_t value; std::uint8_t base; std::size_t n_bits; };
        const Case cases[] = {
            {0b1011, 2, 6},   // 值=11,  二进制, 6位
            {5, 2, 4},         // 值=5,   二进制, 4位
            {10, 2, 4},        // 值=10,  二进制, 4位
            {0, 2, 4},         // 值=0,   二进制, 4位 (边界)
            {15, 3, 3},        // 值=15,  三进制, 3位
            {8, 3, 4},         // 值=8,   三进制, 4位
            {123, 5, 4},       // 值=123, 五进制, 4位
            {100, 7, 5},       // 值=100, 七进制, 5位
        };
        int case_idx = 0;
        for (const auto& c : cases) {
            auto digits = whir::base_decomposition(c.value, c.base, c.n_bits);
            std::printf("CASE %d base_decomposition v=%zu b=%u n=%zu\n",
                case_idx, c.value, (unsigned)c.base, c.n_bits);
            std::printf("  digits");
            for (auto d : digits) std::printf(" %u", (unsigned)d);
            std::printf("\n"); ++case_idx;
        }

        // expand_randomness: 等价于 geometric_sequence, 长度 6
        Lcg rng(0x9999999999999999ULL);
        Goldilocks base = Goldilocks::from_u64(rng.next());
        auto seq = whir::expand_randomness<Goldilocks>(base, 6);
        std::printf("CASE 8 expand_randomness\n"); dump_base_vec("seq", seq);
    }
    return 0;
}
