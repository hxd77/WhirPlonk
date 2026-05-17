// 生成 Goldilocks / Ext2 / Ext3 的 golden vectors，用于和 Rust 原版对拍。
// 必须和 examples/dump_golden_algebra.rs 产生逐字节相同的输出。
//
// 构建：见 cpp/CMakeLists.txt 里新增的 dump_golden_algebra 目标
// 运行：./dump_golden_algebra > golden_cpp.txt

#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/goldilocks_ext2.hpp"
#include "whir/algebra/goldilocks_ext3.hpp"
#include "whir/algebra/linear_form.hpp"
#include "whir/algebra/multilinear.hpp"
#include "whir/algebra/ntt/cooley_tukey.hpp"
#include "whir/algebra/ntt/cooley_tukey_goldilocks.hpp"
#include "whir/algebra/ntt/transpose.hpp"
#include "whir/algebra/ntt/wavelet.hpp"
#include "whir/algebra/sumcheck.hpp"
#include "whir/algebra/utilities.hpp"
#include "whir/hash/blake3_engine.hpp"
#include "whir/hash/copy_engine.hpp"
#include "whir/hash/hash_engine.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/protocols/challenge_indices.hpp"
#include "whir/protocols/matrix_commit.hpp"
#include "whir/protocols/merkle_tree.hpp"
#include "whir/protocols/proof_of_work.hpp"
#include "whir/utils.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

using whir::algebra::Goldilocks;
using whir::algebra::GoldilocksExt2;
using whir::algebra::GoldilocksExt3;

// 必须和 Rust 侧 Lcg 完全一致的 LCG
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};

static void print_base(const char* label, Goldilocks a) {
    std::printf("%s %llu\n", label, (unsigned long long)a.as_canonical_u64());
}

static void print_ext2(const char* label, GoldilocksExt2 a) {
    std::printf("%s %llu %llu\n", label, //llu表示long long unsigned
        (unsigned long long)a.c0().as_canonical_u64(),
        (unsigned long long)a.c1().as_canonical_u64());
}

static void print_ext3(const char* label, GoldilocksExt3 a) {
    std::printf("%s %llu %llu %llu\n", label,
        (unsigned long long)a.c0().as_canonical_u64(),
        (unsigned long long)a.c1().as_canonical_u64(),
        (unsigned long long)a.c2().as_canonical_u64());
}

int main() {
    Lcg rng(0xCAFEBABEDEADBEEFULL);

    std::printf("# SECTION base\n");
    for (int i = 0; i < 3; ++i) {
        uint64_t a_raw = rng.next();
        uint64_t b_raw = rng.next();
        auto a = Goldilocks::from_u64(a_raw);
        auto b = Goldilocks::from_u64(b_raw);

        std::printf("CASE %d %llu %llu\n", i,
            (unsigned long long)a_raw, (unsigned long long)b_raw);
        print_base("  add", a + b);
        print_base("  sub", a - b);
        print_base("  neg", -a);
        print_base("  mul", a * b);
        print_base("  sq",  a.square());
        if (!a.is_zero()) {
            print_base("  inv", a.inverse());
        }
        print_base("  pow10", a.pow(10));
    }

    std::printf("# SECTION ext2\n");
    for (int i = 0; i < 3; ++i) {
        uint64_t a0 = rng.next();
        uint64_t a1 = rng.next();
        uint64_t b0 = rng.next();
        uint64_t b1 = rng.next();
        GoldilocksExt2 a{Goldilocks::from_u64(a0), Goldilocks::from_u64(a1)};
        GoldilocksExt2 b{Goldilocks::from_u64(b0), Goldilocks::from_u64(b1)};

        std::printf("CASE %d %llu %llu %llu %llu\n", i,
            (unsigned long long)a0, (unsigned long long)a1,
            (unsigned long long)b0, (unsigned long long)b1);
        print_ext2("  add", a + b);
        print_ext2("  sub", a - b);
        print_ext2("  mul", a * b);
        print_ext2("  sq",  a * a);
        if (!(a == GoldilocksExt2::zero())) {
            print_ext2("  inv", a.inverse());
        }
        print_ext2("  frob1", a.frobenius_map(1));
    }

    std::printf("# SECTION ext3\n");
    for (int i = 0; i < 3; ++i) {
        uint64_t a0 = rng.next();
        uint64_t a1 = rng.next();
        uint64_t a2 = rng.next();
        uint64_t b0 = rng.next();
        uint64_t b1 = rng.next();
        uint64_t b2 = rng.next();
        GoldilocksExt3 a{Goldilocks::from_u64(a0), Goldilocks::from_u64(a1), Goldilocks::from_u64(a2)};
        GoldilocksExt3 b{Goldilocks::from_u64(b0), Goldilocks::from_u64(b1), Goldilocks::from_u64(b2)};

        std::printf("CASE %d %llu %llu %llu %llu %llu %llu\n", i,
            (unsigned long long)a0, (unsigned long long)a1, (unsigned long long)a2,
            (unsigned long long)b0, (unsigned long long)b1, (unsigned long long)b2);
        print_ext3("  add", a + b);
        print_ext3("  sub", a - b);
        print_ext3("  mul", a * b);
        print_ext3("  sq",  a * a);
        if (!(a == GoldilocksExt3::zero())) {
            print_ext3("  inv", a.inverse());
        }
        print_ext3("  frob1", a.frobenius_map(1));
    }

    // ====================================================================
    // 以下各 section 用独立 seed, 与 Rust 端字节级对齐。
    // ====================================================================
    //打印域元素向量
    auto dump_base_vec = [](const char* label, const std::vector<Goldilocks>& v) { //[]是C++的lambda捕获列表,表示不捕获任何外部变量,只能使用自己的参数
        std::printf("  %s %zu\n", label, v.size());
        for (const auto& x : v) {
            std::printf("     %llu\n", (unsigned long long)x.as_canonical_u64()); //把Goldilocks元素还原为标准uint64_t
        }
    };

    std::printf("# SECTION utilities\n");
    {
        Lcg rng(0x1111111111111111ULL);

        // CASE 0: geometric_sequence(base, length=8)
        Goldilocks base = Goldilocks::from_u64(rng.next());
        std::printf("CASE 0 geometric_sequence\n");
        auto seq = whir::algebra::geometric_sequence<Goldilocks>(base, 8);
        dump_base_vec("seq", seq);

        // CASE 1: dot(a[8], b[8])
        std::vector<Goldilocks> a, b;
        for (int i = 0; i < 8; ++i) a.push_back(Goldilocks::from_u64(rng.next()));
        for (int i = 0; i < 8; ++i) b.push_back(Goldilocks::from_u64(rng.next()));
        std::printf("CASE 1 dot\n");
        print_base("  result", whir::algebra::dot<Goldilocks>(
            std::span<const Goldilocks>{a}, std::span<const Goldilocks>{b}));

        // CASE 2: tensor_product(a[3], b[2])
        std::vector<Goldilocks> aa, bb;
        for (int i = 0; i < 3; ++i) aa.push_back(Goldilocks::from_u64(rng.next()));
        for (int i = 0; i < 2; ++i) bb.push_back(Goldilocks::from_u64(rng.next()));
        std::printf("CASE 2 tensor_product\n");
        auto tp = whir::algebra::tensor_product<Goldilocks>(
            std::span<const Goldilocks>{aa}, std::span<const Goldilocks>{bb});
        dump_base_vec("tp", tp);

        // CASE 3: univariate_evaluate(coeffs[8], x)
        std::vector<Goldilocks> coeffs;
        for (int i = 0; i < 8; ++i) coeffs.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks x = Goldilocks::from_u64(rng.next());
        std::printf("CASE 3 univariate_evaluate\n");
        print_base("  result", whir::algebra::univariate_evaluate<Goldilocks>(
            std::span<const Goldilocks>{coeffs}, x));

        // CASE 4: scalar_mul_add(acc, w, vec) — 长度 8
        std::vector<Goldilocks> acc;
        for (int i = 0; i < 8; ++i) acc.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks w = Goldilocks::from_u64(rng.next());
        std::vector<Goldilocks> vec_in;
        for (int i = 0; i < 8; ++i) vec_in.push_back(Goldilocks::from_u64(rng.next()));
        whir::algebra::scalar_mul_add<Goldilocks>(
            std::span<Goldilocks>{acc}, w, std::span<const Goldilocks>{vec_in});
        std::printf("CASE 4 scalar_mul_add\n");
        dump_base_vec("acc", acc);

        // CASE 5: geometric_accumulate(acc[8], scalars[3], points[3])
        std::vector<Goldilocks> acc2;
        for (int i = 0; i < 8; ++i) acc2.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<Goldilocks> scalars;
        for (int i = 0; i < 3; ++i) scalars.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<Goldilocks> points;
        for (int i = 0; i < 3; ++i) points.push_back(Goldilocks::from_u64(rng.next()));
        whir::algebra::geometric_accumulate<Goldilocks>(
            std::span<Goldilocks>{acc2}, std::move(scalars),
            std::span<const Goldilocks>{points});
        std::printf("CASE 5 geometric_accumulate\n");
        dump_base_vec("acc", acc2);
    }

    std::printf("# SECTION multilinear\n");
    {
        Lcg rng(0x2222222222222222ULL);

        // CASE 0/1/2: multilinear_extend, k=3/4/5
        int case_idx = 0;
        for (int k : {3, 4, 5}) {
            const std::size_t n = std::size_t{1} << k;
            std::vector<Goldilocks> evals;
            for (std::size_t i = 0; i < n; ++i) evals.push_back(Goldilocks::from_u64(rng.next()));
            std::vector<Goldilocks> point;
            for (int i = 0; i < k; ++i) point.push_back(Goldilocks::from_u64(rng.next()));
            std::printf("CASE %d multilinear_extend k=%d\n", case_idx++, k);
            print_base("  result", whir::algebra::multilinear_extend<Goldilocks>(
                std::span<const Goldilocks>{evals}, std::span<const Goldilocks>{point}));
        }

        // CASE 3: eval_eq with point of size 3
        std::vector<Goldilocks> point3;
        for (int i = 0; i < 3; ++i) point3.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks scalar3 = Goldilocks::from_u64(rng.next());
        std::vector<Goldilocks> acc3(8, Goldilocks::zero());
        whir::algebra::eval_eq<Goldilocks>(
            std::span<Goldilocks>{acc3}, std::span<const Goldilocks>{point3}, scalar3);
        std::printf("CASE 3 eval_eq k=3\n");
        dump_base_vec("acc", acc3);

        // CASE 4: eval_eq with point of size 4
        std::vector<Goldilocks> point4;
        for (int i = 0; i < 4; ++i) point4.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks scalar4 = Goldilocks::from_u64(rng.next());
        std::vector<Goldilocks> acc4(16, Goldilocks::zero());
        whir::algebra::eval_eq<Goldilocks>(
            std::span<Goldilocks>{acc4}, std::span<const Goldilocks>{point4}, scalar4);
        std::printf("CASE 4 eval_eq k=4\n");
        dump_base_vec("acc", acc4);
    }

    std::printf("# SECTION sumcheck\n");
    {
        Lcg rng(0x3333333333333333ULL);

        // CASE 0/1: compute_sumcheck_polynomial, n=8/16
        int case_idx = 0;
        for (std::size_t n : {std::size_t{8}, std::size_t{16}}) {
            std::vector<Goldilocks> a, b;
            for (std::size_t i = 0; i < n; ++i) a.push_back(Goldilocks::from_u64(rng.next()));
            for (std::size_t i = 0; i < n; ++i) b.push_back(Goldilocks::from_u64(rng.next()));
            auto [acc0, acc2] = whir::algebra::compute_sumcheck_polynomial<Goldilocks>(
                std::span<const Goldilocks>{a}, std::span<const Goldilocks>{b});
            std::printf("CASE %d compute_sumcheck_polynomial n=%zu\n", case_idx++, n);
            print_base("  acc0", acc0);
            print_base("  acc2", acc2);
        }

        // CASE 2: fold(values[16], weight) → 长度 8
        std::vector<Goldilocks> values;
        for (int i = 0; i < 16; ++i) values.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks weight = Goldilocks::from_u64(rng.next());
        whir::algebra::fold<Goldilocks>(values, weight);
        std::printf("CASE 2 fold n=16\n");
        dump_base_vec("folded", values);
    }

    std::printf("# SECTION ntt\n");
    {
        Lcg rng(0x4444444444444444ULL);
        auto& engine = whir::algebra::ntt::goldilocks_engine();

        int case_idx = 0;
        for (std::size_t n : {std::size_t{4}, std::size_t{8}, std::size_t{16}, std::size_t{64}}) {
            std::vector<Goldilocks> values;
            for (std::size_t i = 0; i < n; ++i) values.push_back(Goldilocks::from_u64(rng.next()));
            engine.ntt(std::span<Goldilocks>{values});
            std::printf("CASE %d ntt n=%zu\n", case_idx++, n);
            dump_base_vec("out", values);
        }
    }

    std::printf("# SECTION wavelet\n");
    {
        Lcg rng(0x5555555555555555ULL);

        int case_idx = 0;
        for (std::size_t n : {std::size_t{8}, std::size_t{64}}) {
            std::vector<Goldilocks> values;
            for (std::size_t i = 0; i < n; ++i) values.push_back(Goldilocks::from_u64(rng.next()));
            whir::algebra::ntt::wavelet_transform<Goldilocks>(std::span<Goldilocks>{values});
            std::printf("CASE %d wavelet n=%zu\n", case_idx++, n);
            dump_base_vec("out", values);
        }
    }

    std::printf("# SECTION transpose\n");
    {
        Lcg rng(0x6666666666666666ULL);

        // CASE 0: 8x4 矩阵转置 (这里直接用 u64 元素, 与 Rust 端一致)
        const std::size_t rows = 8, cols = 4;
        std::vector<uint64_t> m;
        for (std::size_t i = 0; i < rows * cols; ++i) m.push_back(rng.next());
        whir::algebra::ntt::transpose<uint64_t>(std::span<uint64_t>{m}, rows, cols);
        std::printf("CASE 0 transpose 8x4\n");
        for (auto v : m) std::printf("  %llu\n", (unsigned long long)v);
    }

    std::printf("# SECTION linear_form\n");
    {
        using whir::algebra::Covector;
        using whir::algebra::MultilinearExtension;
        using whir::algebra::UnivariateEvaluation;
        Lcg rng(0x7777777777777777ULL);

        // Covector(vector[8])
        std::vector<Goldilocks> cv_vec;
        for (int i = 0; i < 8; ++i) cv_vec.push_back(Goldilocks::from_u64(rng.next()));
        Covector<Goldilocks> cv{std::move(cv_vec)};
        std::vector<Goldilocks> pt3;
        for (int i = 0; i < 3; ++i) pt3.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks scalar = Goldilocks::from_u64(rng.next());
        std::printf("CASE 0 covector\n");
        print_base("  size", Goldilocks::from_u64(static_cast<uint64_t>(cv.size())));
        print_base("  mle_evaluate", cv.mle_evaluate(std::span<const Goldilocks>{pt3}));
        std::vector<Goldilocks> acc(8, Goldilocks::zero());
        cv.accumulate(std::span<Goldilocks>{acc}, scalar);
        dump_base_vec("accumulate", acc);

        // MultilinearExtension(point[3])
        std::vector<Goldilocks> mle_point;
        for (int i = 0; i < 3; ++i) mle_point.push_back(Goldilocks::from_u64(rng.next()));
        MultilinearExtension<Goldilocks> mle{std::move(mle_point)};
        std::vector<Goldilocks> pt3b;
        for (int i = 0; i < 3; ++i) pt3b.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks scalar2 = Goldilocks::from_u64(rng.next());
        std::printf("CASE 1 multilinear_extension\n");
        print_base("  size", Goldilocks::from_u64(static_cast<uint64_t>(mle.size())));
        print_base("  mle_evaluate", mle.mle_evaluate(std::span<const Goldilocks>{pt3b}));
        std::vector<Goldilocks> acc1(8, Goldilocks::zero());
        mle.accumulate(std::span<Goldilocks>{acc1}, scalar2);
        dump_base_vec("accumulate", acc1);

        // UnivariateEvaluation(x, size=8)
        Goldilocks x = Goldilocks::from_u64(rng.next());
        UnivariateEvaluation<Goldilocks> ue{x, 8};
        std::vector<Goldilocks> pt3c;
        for (int i = 0; i < 3; ++i) pt3c.push_back(Goldilocks::from_u64(rng.next()));
        Goldilocks scalar3 = Goldilocks::from_u64(rng.next());
        std::printf("CASE 2 univariate_evaluation\n");
        print_base("  size", Goldilocks::from_u64(static_cast<uint64_t>(ue.size())));
        print_base("  mle_evaluate", ue.mle_evaluate(std::span<const Goldilocks>{pt3c}));
        std::vector<Goldilocks> acc2(8, Goldilocks::zero());
        ue.accumulate(std::span<Goldilocks>{acc2}, scalar3);
        dump_base_vec("accumulate", acc2);

        // accumulate_many: 3 个 evaluator
        std::vector<UnivariateEvaluation<Goldilocks>> evaluators;
        for (int i = 0; i < 3; ++i) {
            evaluators.emplace_back(Goldilocks::from_u64(rng.next()), 8);
        }
        std::vector<Goldilocks> scalars;
        for (int i = 0; i < 3; ++i) scalars.push_back(Goldilocks::from_u64(rng.next()));
        std::vector<Goldilocks> acc3(8, Goldilocks::zero());
        UnivariateEvaluation<Goldilocks>::accumulate_many(
            evaluators, std::span<Goldilocks>{acc3}, std::span<const Goldilocks>{scalars});
        std::printf("CASE 3 univariate_accumulate_many\n");
        dump_base_vec("acc", acc3);
    }

    std::printf("# SECTION utils\n");
    {
        // base_decomposition: 与 Rust 同样的固定 case。
        struct Case { std::size_t value; std::uint8_t base; std::size_t n_bits; };
        const Case cases[] = {
            {0b1011, 2, 6},
            {5, 2, 4},
            {10, 2, 4},
            {0, 2, 4},
            {15, 3, 3},
            {8, 3, 4},
            {123, 5, 4},
            {100, 7, 5},
        };
        int case_idx = 0;
        for (const auto& c : cases) {
            auto digits = whir::base_decomposition(c.value, c.base, c.n_bits);
            std::printf("CASE %d base_decomposition v=%zu b=%u n=%zu\n",
                case_idx, c.value, static_cast<unsigned>(c.base), c.n_bits);
            std::printf("  digits");
            for (auto d : digits) std::printf(" %u", static_cast<unsigned>(d));
            std::printf("\n");
            ++case_idx;
        }

        // expand_randomness 用 Goldilocks 测一组。
        Lcg rng(0x9999999999999999ULL);
        Goldilocks base = Goldilocks::from_u64(rng.next());
        auto seq = whir::expand_randomness<Goldilocks>(base, 6);
        std::printf("CASE 8 expand_randomness\n");
        dump_base_vec("seq", seq);
    }

    std::printf("# SECTION hash\n");
    {
        Lcg rng(0xAAAAAAAAAAAAAAAAULL);

        auto print_hash = [&](const char* label, const whir::hash::Hash& h) {
            std::printf("  %s ", label);
            for (auto byte : h) std::printf("%02x", static_cast<unsigned>(byte));
            std::printf("\n");
        };

        // 与 Rust 端字节级一致的 LCG 取字节: 每次取 u64 转 little-endian 8 字节, 拼到 v 满 n 个为止。
        auto make_bytes = [&](std::size_t n) {
            std::vector<std::uint8_t> v;
            v.reserve(n);
            while (v.size() < n) {
                std::uint64_t w = rng.next();
                for (int i = 0; i < 8 && v.size() < n; ++i) {
                    v.push_back(static_cast<std::uint8_t>(w & 0xFFu));
                    w >>= 8;
                }
            }
            return v;
        };

        auto run = [&](int case_idx, const whir::hash::HashEngine& engine,
                       const char* label, std::size_t size, std::size_t count) {
            auto input = make_bytes(size * count);
            std::vector<whir::hash::Hash> output(count);
            engine.hash_many(size,
                std::span<const std::uint8_t>{input.data(), input.size()},
                std::span<whir::hash::Hash>{output.data(), output.size()});
            std::printf("CASE %d %s size=%zu count=%zu\n", case_idx, label, size, count);
            for (std::size_t i = 0; i < output.size(); ++i) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "h%zu", i);
                print_hash(buf, output[i]);
            }
        };

        whir::hash::Copy copy_eng;
        whir::hash::Blake3 blake3_eng;
        whir::hash::Sha2 sha2_eng;

        run(0, copy_eng,   "copy",   0,    2);
        run(1, copy_eng,   "copy",   16,   2);
        run(2, copy_eng,   "copy",   32,   3);
        run(3, blake3_eng, "blake3", 64,   1);
        run(4, blake3_eng, "blake3", 64,   4);
        run(5, blake3_eng, "blake3", 128,  2);
        run(6, blake3_eng, "blake3", 256,  1);
        run(7, blake3_eng, "blake3", 1024, 1);
        run(8, sha2_eng,   "sha2",   0,    1);
        run(9, sha2_eng,   "sha2",   31,   1);
        run(10, sha2_eng,  "sha2",   32,   3);
        run(11, sha2_eng,  "sha2",   64,   2);
        run(12, sha2_eng,  "sha2",   100,  2);
    }

    // 与 Rust dumper 共用的 dump_hash: 一行 "  label <64 hex chars>"。
    auto dump_hash = [](const char* label, const whir::hash::Hash& h) {
        std::printf("  %s ", label);
        for (auto byte : h) std::printf("%02x", static_cast<unsigned>(byte));
        std::printf("\n");
    };

    std::printf("# SECTION merkle_tree\n");
    {
        namespace mt = whir::protocols::merkle_tree;
        using whir::hash::Hash;

        whir::hash::Blake3 blake3_eng;
        whir::hash::Sha2 sha2_eng;

        auto engine_lookup = [&](whir::EngineId id) -> const whir::hash::HashEngine& {
            if (id == whir::hash::ENGINE_ID_BLAKE3) return blake3_eng;
            if (id == whir::hash::ENGINE_ID_SHA2)   return sha2_eng;
            std::abort();
        };

        struct Case {
            const char* label;
            whir::EngineId hash_id;
            std::size_t num_leaves;
            std::vector<std::size_t> indices;
        };
        const std::vector<Case> cases = {
            {"blake3-16-2", whir::hash::ENGINE_ID_BLAKE3, 16, {3, 5, 11}},
            {"blake3-32-3", whir::hash::ENGINE_ID_BLAKE3, 32, {0, 1, 2, 31}},
            {"sha2-8-2",    whir::hash::ENGINE_ID_SHA2,    8, {2, 6}},
        };

        for (std::size_t case_idx = 0; case_idx < cases.size(); ++case_idx) {
            const auto& c = cases[case_idx];

            //生成 deterministic leaves: 第 i 个叶子第 j 字节 = (i*31 + j) & 0xFF, 与 Rust 端一致。
            std::vector<Hash> leaves(c.num_leaves);
            for (std::size_t i = 0; i < c.num_leaves; ++i) {
                for (std::size_t j = 0; j < 32; ++j) {
                    leaves[i][j] = static_cast<std::uint8_t>((i * 31 + j) & 0xFF);
                }
            }

            auto cfg = mt::make_config(c.hash_id, c.num_leaves);
            auto witness = mt::build_tree(cfg, leaves, engine_lookup);
            const auto layers = mt::layers_for_size(c.num_leaves);
            const auto leaf_layer = std::size_t{1} << layers;
            const auto root = mt::tree_root(witness);
            auto hints = mt::open_path(cfg, witness,
                std::span<const std::size_t>{c.indices.data(), c.indices.size()});

            std::printf("CASE %zu %s num_leaves=%zu\n", case_idx, c.label, c.num_leaves);
            dump_hash("root", root);
            std::printf("  leaf_layer %zu\n", leaf_layer);
            std::printf("  num_hints %zu\n", hints.size());
            for (std::size_t i = 0; i < hints.size(); ++i) {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "hint%zu", i);
                dump_hash(buf, hints[i]);
            }
        }
    }

    std::printf("# SECTION pow\n");
    {
        using whir::hash::Hash;

        whir::hash::Blake3 blake3_eng;
        whir::hash::Sha2 sha2_eng;

        struct Case {
            const char* label;
            const whir::hash::HashEngine* engine;
            std::uint64_t threshold;
            std::uint8_t challenge_byte;
        };
        const std::vector<Case> cases = {
            {"blake3-thr60bits", &blake3_eng, std::uint64_t{1} << 60, 0xAA},
            {"sha2-thr60bits",   &sha2_eng,   std::uint64_t{1} << 60, 0x55},
        };

        for (std::size_t case_idx = 0; case_idx < cases.size(); ++case_idx) {
            const auto& c = cases[case_idx];

            std::array<std::uint8_t, 32> challenge{};
            challenge.fill(c.challenge_byte);

            //同 Rust dumper: 单线程顺序扫描, 找最小满足 nonce, 与并行版本结果一致。
            const std::size_t batch = std::max<std::size_t>(c.engine->preferred_batch_size(), 1);
            std::vector<std::uint8_t> inputs(64 * batch, 0);
            std::vector<Hash> outputs(batch);
            for (std::size_t i = 0; i < batch; ++i) {
                std::memcpy(&inputs[64 * i], challenge.data(), 32);
            }

            std::uint64_t found_nonce = 0;
            bool found = false;
            for (std::uint64_t base = 0; !found; base += batch) {
                for (std::size_t i = 0; i < batch; ++i) {
                    const std::uint64_t n = base + static_cast<std::uint64_t>(i);
                    for (int b = 0; b < 8; ++b) {
                        inputs[64 * i + 32 + b] =
                            static_cast<std::uint8_t>((n >> (8 * b)) & 0xFFu);
                    }
                }
                c.engine->hash_many(64,
                    std::span<const std::uint8_t>{inputs.data(), inputs.size()},
                    std::span<Hash>{outputs.data(), outputs.size()});
                for (std::size_t i = 0; i < batch; ++i) {
                    std::uint64_t v = 0;
                    for (int b = 7; b >= 0; --b) {
                        v = (v << 8) | static_cast<std::uint64_t>(outputs[i][b]);
                    }
                    if (v <= c.threshold) {
                        found_nonce = base + static_cast<std::uint64_t>(i);
                        found = true;
                        break;
                    }
                }
            }

            //再哈希一次得到正式输出哈希 (用于对拍)
            std::array<std::uint8_t, 64> single{};
            std::memcpy(single.data(), challenge.data(), 32);
            for (int b = 0; b < 8; ++b) {
                single[32 + b] = static_cast<std::uint8_t>((found_nonce >> (8 * b)) & 0xFFu);
            }
            Hash single_out{};
            c.engine->hash_many(64,
                std::span<const std::uint8_t>{single.data(), single.size()},
                std::span<Hash>{&single_out, 1});

            std::printf("CASE %zu %s threshold=%llu\n",
                case_idx, c.label, (unsigned long long)c.threshold);
            std::printf("  nonce %llu\n", (unsigned long long)found_nonce);
            dump_hash("hash", single_out);
        }
    }

    //matrix_commit: 编码 + 行哈希。与 Rust ArkFieldEncoder + hash_many 字节级一致。
    std::printf("# SECTION matrix_commit\n");
    {
        namespace mc = whir::protocols::matrix_commit;
        using whir::hash::Hash;

        whir::hash::Copy copy_eng;
        whir::hash::Blake3 blake3_eng;
        whir::hash::Sha2 sha2_eng;

        Lcg rng(0xBBBBBBBBBBBBBBBBULL);

        auto run_leaves = [&](std::size_t case_idx, const char* label,
                              const whir::hash::HashEngine& engine,
                              const std::vector<Hash>& leaves,
                              std::size_t num_rows, std::size_t num_cols, std::size_t msg_size) {
            (void)engine;
            std::printf("CASE %zu %s rows=%zu cols=%zu msg_size=%zu\n",
                case_idx, label, num_rows, num_cols, msg_size);
            for (std::size_t i = 0; i < leaves.size(); ++i) {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "leaf%zu", i);
                dump_hash(buf, leaves[i]);
            }
        };

        //CASE 0: Goldilocks, Blake3, 4 × 8 (msg = 64)
        {
            const std::size_t num_rows = 4, num_cols = 8;
            const std::size_t total = num_rows * num_cols;
            std::vector<Goldilocks> matrix;
            matrix.reserve(total);
            for (std::size_t i = 0; i < total; ++i) {
                matrix.push_back(Goldilocks::from_u64(rng.next()));
            }
            std::vector<Hash> leaves(num_rows);
            mc::commit_leaves<Goldilocks>(blake3_eng,
                std::span<const Goldilocks>{matrix}, num_cols,
                std::span<Hash>{leaves});
            const std::size_t msg_size = mc::encoded_size<Goldilocks>() * num_cols;
            run_leaves(0, "field64-blake3", blake3_eng, leaves, num_rows, num_cols, msg_size);
        }

        //CASE 1: GoldilocksExt2, Blake3, 2 × 8 (msg = 128)
        {
            const std::size_t num_rows = 2, num_cols = 8;
            const std::size_t total = num_rows * num_cols;
            std::vector<GoldilocksExt2> matrix;
            matrix.reserve(total);
            //C++ 函数实参求值顺序未定义, 必须用具名局部变量强制 LTR 求值, 否则与 Rust 不一致。
            for (std::size_t i = 0; i < total; ++i) {
                const auto c0 = Goldilocks::from_u64(rng.next());
                const auto c1 = Goldilocks::from_u64(rng.next());
                matrix.emplace_back(c0, c1);
            }
            std::vector<Hash> leaves(num_rows);
            mc::commit_leaves<GoldilocksExt2>(blake3_eng,
                std::span<const GoldilocksExt2>{matrix}, num_cols,
                std::span<Hash>{leaves});
            const std::size_t msg_size = mc::encoded_size<GoldilocksExt2>() * num_cols;
            run_leaves(1, "field64_2-blake3", blake3_eng, leaves, num_rows, num_cols, msg_size);
        }

        //CASE 2: GoldilocksExt3, Sha2, 3 × 5 (msg = 120)
        {
            const std::size_t num_rows = 3, num_cols = 5;
            const std::size_t total = num_rows * num_cols;
            std::vector<GoldilocksExt3> matrix;
            matrix.reserve(total);
            for (std::size_t i = 0; i < total; ++i) {
                const auto c0 = Goldilocks::from_u64(rng.next());
                const auto c1 = Goldilocks::from_u64(rng.next());
                const auto c2 = Goldilocks::from_u64(rng.next());
                matrix.emplace_back(c0, c1, c2);
            }
            std::vector<Hash> leaves(num_rows);
            mc::commit_leaves<GoldilocksExt3>(sha2_eng,
                std::span<const GoldilocksExt3>{matrix}, num_cols,
                std::span<Hash>{leaves});
            const std::size_t msg_size = mc::encoded_size<GoldilocksExt3>() * num_cols;
            run_leaves(2, "field64_3-sha2", sha2_eng, leaves, num_rows, num_cols, msg_size);
        }

        //CASE 3: Goldilocks, Sha2, 2 × 4 (msg = 32)
        {
            const std::size_t num_rows = 2, num_cols = 4;
            const std::size_t total = num_rows * num_cols;
            std::vector<Goldilocks> matrix;
            matrix.reserve(total);
            for (std::size_t i = 0; i < total; ++i) {
                matrix.push_back(Goldilocks::from_u64(rng.next()));
            }
            std::vector<Hash> leaves(num_rows);
            mc::commit_leaves<Goldilocks>(sha2_eng,
                std::span<const Goldilocks>{matrix}, num_cols,
                std::span<Hash>{leaves});
            const std::size_t msg_size = mc::encoded_size<Goldilocks>() * num_cols;
            run_leaves(3, "field64-sha2", sha2_eng, leaves, num_rows, num_cols, msg_size);
        }

        //CASE 4: Goldilocks, Copy, 3 × 4 (msg = 32)
        {
            const std::size_t num_rows = 3, num_cols = 4;
            const std::size_t total = num_rows * num_cols;
            std::vector<Goldilocks> matrix;
            matrix.reserve(total);
            for (std::size_t i = 0; i < total; ++i) {
                matrix.push_back(Goldilocks::from_u64(rng.next()));
            }
            std::vector<Hash> leaves(num_rows);
            mc::commit_leaves<Goldilocks>(copy_eng,
                std::span<const Goldilocks>{matrix}, num_cols,
                std::span<Hash>{leaves});
            const std::size_t msg_size = mc::encoded_size<Goldilocks>() * num_cols;
            run_leaves(4, "field64-copy", copy_eng, leaves, num_rows, num_cols, msg_size);
        }
    }

    //challenge_indices 纯函数: entropy bytes → indices, 与 Rust dumper 字节级一致。
    std::printf("# SECTION challenge_indices\n");
    {
        namespace ci = whir::protocols::challenge_indices;

        struct Case {
            const char* label;
            std::size_t num_leaves;
            std::size_t count;
            bool dedup;
            std::vector<std::uint8_t> entropy;
        };

        const std::vector<Case> cases = {
            {"128-5-dedup",     128,                5, true,  {0x01,0x23,0x45,0x67,0x89}},
            {"128-5-nodedup",   128,                5, false, {0x01,0x23,0x45,0x67,0x89}},
            {"8192-5-dedup",    8192,               5, true,  {0x01,0x23, 0x45,0x67, 0x89,0xAB, 0xCD,0xEF, 0x12,0x34}},
            {"1m-4-dedup",      std::size_t{1}<<20, 4, true,  {0x12,0x34,0x56, 0x78,0x9A,0xBC, 0xDE,0xF0,0x11, 0x22,0x33,0x44}},
            {"128-5-dups",      128,                5, true,  {0x20,0x40,0x20,0x60,0x40}},
            {"1leaf-3-dedup",   1,                  3, true,  {}},
            {"1leaf-3-nodedup", 1,                  3, false, {}},
            {"0count",          8,                  0, true,  {}},
        };

        for (std::size_t case_idx = 0; case_idx < cases.size(); ++case_idx) {
            const auto& c = cases[case_idx];
            auto result = ci::indices_from_entropy(
                std::span<const std::uint8_t>{c.entropy.data(), c.entropy.size()},
                c.num_leaves, c.count, c.dedup);
            std::printf("CASE %zu %s num_leaves=%zu count=%zu dedup=%s entropy_len=%zu\n",
                case_idx, c.label, c.num_leaves, c.count,
                c.dedup ? "true" : "false",
                c.entropy.size());
            std::printf("  indices");
            for (auto v : result) std::printf(" %zu", v);
            std::printf("\n");
        }
    }

    return 0;
}
