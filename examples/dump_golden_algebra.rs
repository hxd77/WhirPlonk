// ===========================================================================
// dump_golden_algebra.rs
// 生成 Goldilocks 域及其扩域的 golden vectors，用于和 C++ 移植对拍。
//
// 运行: cargo run --example dump_golden_algebra --release > golden_rs.txt
// 对拍: diff <(tr -d '\r' < golden_rs.txt) golden_cpp.txt
//
// 整体结构:
//   1. LCG 确定性伪随机数生成器（Rust/C++ 两边种子和算法完全一致）
//   2. 打印辅助函数（把域元素还原成大整数打印）
//   3. 每个 SECTION 测试一个子模块，用独立 seed 重置 LCG
//      - 独立 seed 保证新增 section 不影响已有 section 的输出
//   4. 输出格式: "# SECTION <name>" 标记段落, "CASE <id> <params>" 标记用例
//
// 对应 C++ 文件: cpp/tests/dump_golden_algebra.cpp
// ===========================================================================

use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use whir::algebra::fields::{Field64, Field64_2, Field64_3};
use whir::algebra::{
    self,
    linear_form::{Covector, MultilinearExtension, UnivariateEvaluation},
    ntt,
};
use whir::utils::{base_decomposition, expand_randomness};
use whir::engines::EngineId;
use whir::hash::{Hash, BLAKE3, COPY, SHA2, ENGINES};
use whir::protocols::matrix_commit::Encodable;
use zerocopy::IntoBytes;

// ===========================================================================
// LCG — 线性同余生成器 (Linear Congruential Generator)
///
// 公式: X_{n+1} = (a * X_n + c) mod 2^64
//   a = 6364136223846793005 (乘数)
//   c = 1442695040888963407 (增量)
//
// 这是 Numerical Recipes 中的经典参数。Rust/C++ 两边用相同的种子
// 0xCAFEBABE_DEADBEEF, 保证生成的伪随机序列逐位完全一致。
//
// 每个 SECTION 可以 reset 自己的种子（例如 0x1111_1111_1111_1111），
// 这样新增 section 不会打乱已有 section 的随机序列和输出。
// ===========================================================================
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }

    fn next_u64(&mut self) -> u64 {
        // wrapping_mul / wrapping_add: 自动溢出截断, 等价于对 2^64 取模
        self.0 = self.0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

// ===========================================================================
// 打印辅助函数
//
// Field64 内部是 Montgomery 形式（为了加速模乘），不是真正的整数值。
// into_bigint() 把 Montgomery 形式还原成标准大整数，再取低 64 位打印。
//
// 这三个函数对应 C++ 侧的 print_base / print_ext2 / print_ext3。
// ===========================================================================

/// 打印基域 Goldilocks (Field64) 元素: "  <label> <u64值>"
fn print_base(label: &str, a: Field64) {
    let v: u64 = a.into_bigint().0[0];
    println!("{label} {v}");
}

/// 打印二次扩域元素: "  <label> <c0> <c1>"
fn print_ext2(label: &str, a: Field64_2) {
    let c0: u64 = a.c0.into_bigint().0[0];
    let c1: u64 = a.c1.into_bigint().0[0];
    println!("{label} {c0} {c1}");
}

/// 打印三次扩域元素: "  <label> <c0> <c1> <c2>"
fn print_ext3(label: &str, a: Field64_3) {
    let c0: u64 = a.c0.into_bigint().0[0];
    let c1: u64 = a.c1.into_bigint().0[0];
    let c2: u64 = a.c2.into_bigint().0[0];
    println!("{label} {c0} {c1} {c2}");
}

fn main() {
    // 全局种子 — 必须和 C++ 侧 Lcg(0xCAFEBABEDEADBEEFULL) 完全一致
    let mut rng = Lcg::new(0xCAFEBABE_DEADBEEF);

    // ========================================================================
    // SECTION base — Goldilocks 基域 (Field64) 的基本运算
    //
    // 测试: 加减取负、乘法、平方、求逆、幂
    // 参数: Goldilocks prime p = 2^64 - 2^32 + 1
    //       每个 CASE 有 a, b 两个随机输入，测试 3 组 (i=0,1,2)
    //
    // 对应 C++: algebra/goldilocks.hpp 的 Goldilocks 类
    // ========================================================================
    println!("# SECTION base");
    for i in 0..3 {
        let a_raw = rng.next_u64();    // 随机 a 的原始 u64 值 (从 LCG 取)
        let b_raw = rng.next_u64();    // 随机 b 的原始 u64 值
        let a = Field64::from(a_raw);  // from() 自动做 mod p 规约 (a_raw >= p 时减 p)
        let b = Field64::from(b_raw);

        // CASE 行格式: "CASE <id> <a_raw> <b_raw>" — 让对拍脚本可验证输入一致
        println!("CASE {i} {a_raw} {b_raw}");

        print_base("  add", a + b);          // 模加
        print_base("  sub", a - b);          // 模减
        print_base("  neg", -a);              // 取负 (p - a)
        print_base("  mul", a * b);           // 模乘
        print_base("  sq",  a.square());      // 平方 a²
        if !a.is_zero() {
            print_base("  inv", a.inverse().unwrap());  // 求逆 a^{-1} mod p (费马小定理)
        }
        print_base("  pow10", a.pow([10u64]));  // a^10 (快速幂)
    }

    // ========================================================================
    // SECTION ext2 — 二次扩域 Fp2 = Fp[X] / (X² - 7)
    //
    // 测试: 加减乘、平方、求逆、Frobenius 自同构
    // 元素: a = a0 + a1·X, b = b0 + b1·X
    // 不可约多项式: X² - 7 (7 是二次非剩余 mod p)
    //
    // 对应 C++: algebra/goldilocks_ext2.hpp 的 GoldilocksExt2 类
    // ========================================================================
    println!("# SECTION ext2");
    for i in 0..3 {
        let a0 = rng.next_u64(); let a1 = rng.next_u64();
        let b0 = rng.next_u64(); let b1 = rng.next_u64();
        let a = Field64_2::new(Field64::from(a0), Field64::from(a1));
        let b = Field64_2::new(Field64::from(b0), Field64::from(b1));

        println!("CASE {i} {a0} {a1} {b0} {b1}");

        print_ext2("  add", a + b);
        print_ext2("  sub", a - b);
        print_ext2("  mul", a * b);
        print_ext2("  sq",  a.square());
        if !a.is_zero() {
            print_ext2("  inv", a.inverse().unwrap());
        }
        // Frobenius 映射: (a0+a1·X)^p → a0 + a1·X^p = a0 + a1·(X²)^{(p-1)/2}·X
        // 参数 1 表示应用一次 Frobenius
        print_ext2("  frob1", a.frobenius_map(1));
    }

    // ========================================================================
    // SECTION ext3 — 三次扩域 Fp3 = Fp[X] / (X³ - 2)
    //
    // 测试: 加减乘、平方、求逆、Frobenius
    // 元素: a = a0 + a1·X + a2·X²
    // 不可约多项式: X³ - 2 (2 是三次非剩余 mod p)
    //
    // 对应 C++: algebra/goldilocks_ext3.hpp 的 GoldilocksExt3 类
    // ========================================================================
    println!("# SECTION ext3");
    for i in 0..3 {
        let a0 = rng.next_u64(); let a1 = rng.next_u64(); let a2 = rng.next_u64();
        let b0 = rng.next_u64(); let b1 = rng.next_u64(); let b2 = rng.next_u64();
        let a = Field64_3::new(Field64::from(a0), Field64::from(a1), Field64::from(a2));
        let b = Field64_3::new(Field64::from(b0), Field64::from(b1), Field64::from(b2));

        println!("CASE {i} {a0} {a1} {a2} {b0} {b1} {b2}");

        print_ext3("  add", a + b);
        print_ext3("  sub", a - b);
        print_ext3("  mul", a * b);
        print_ext3("  sq",  a.square());
        if !a.is_zero() {
            print_ext3("  inv", a.inverse().unwrap());
        }
        print_ext3("  frob1", a.frobenius_map(1));
    }

    // ========================================================================
    // 以下各 SECTION 用独立种子重置 LCG。
    //
    // 设计原因:
    //   - 每个 SECTION 的输出独立于前面 SECTION 的随机序列
    //   - 新增 SECTION 不会改变已有 SECTION 的 golden 输出 (diff 只增不减)
    //   - 如果共用全局种子, 插入新测试会导致后面所有 SECTION 的随机值位移
    //
    // 种子命名规则: 用明显不同的十六进制模式便于识别
    //   0x1111... → utilities
    //   0x2222... → multilinear
    //   0x3333... → sumcheck
    //   ...
    // ========================================================================

    // 向量打印闭包: 输出长度 + 每个元素一行。
    // 格式: "  <label> <len>\n     <v[0]>\n     <v[1]>\n ..."
    let dump_base_vec = |label: &str, v: &[Field64]| {
        println!("  {label} {}", v.len());
        for x in v {
            print_base("    ", *x);
        }
    };

    // ========================================================================
    // SECTION utilities — 代数工具函数
    //
    // 测试: geometric_sequence, dot (内积), tensor_product (张量积),
    //       univariate_evaluate (单变量多项式求值), scalar_mul_add (标量乘加),
    //       geometric_accumulate (几何累加)
    //
    // 对应 C++: algebra/utilities.hpp
    // ========================================================================
    println!("# SECTION utilities");
    {
        let mut rng = Lcg::new(0x1111_1111_1111_1111);

        // --- CASE 0: geometric_sequence(base, length=8) ---
        // 生成 [1, base, base², ..., base⁷], 共 8 项
        // 用于 WHIR 协议中从单个挑战值展开多个随机值
        let base = Field64::from(rng.next_u64());
        println!("CASE 0 geometric_sequence");
        let seq = algebra::geometric_sequence(base, 8);
        dump_base_vec("seq", &seq);

        // --- CASE 1: dot(a[8], b[8]) ---
        // 内积: sum_i a[i] * b[i]
        let a: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let b: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        println!("CASE 1 dot");
        print_base("  result", algebra::dot(&a, &b));

        // --- CASE 2: tensor_product(a[3], b[2]) ---
        // 张量积: c[i*|b| + j] = a[i] * b[j], 输出 3*2=6 个元素
        // 用于 WHIR 中组合多个权重向量
        let aa: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let bb: Vec<_> = (0..2).map(|_| Field64::from(rng.next_u64())).collect();
        println!("CASE 2 tensor_product");
        let tp = algebra::tensor_product(&aa, &bb);
        dump_base_vec("tp", &tp);

        // --- CASE 3: univariate_evaluate(coeffs[8], x) ---
        // 单变量多项式求值 (Horner 法): coeffs[0] + coeffs[1]*x + coeffs[2]*x² + ...
        let coeffs: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let x = Field64::from(rng.next_u64());
        println!("CASE 3 univariate_evaluate");
        print_base("  result", algebra::univariate_evaluate(&coeffs, x));

        // --- CASE 4: scalar_mul_add(acc[8], w, vec[8]) ---
        // 原地: acc[i] += w * vec[i]
        let mut acc: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let w = Field64::from(rng.next_u64());
        let vec_in: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        algebra::scalar_mul_add(&mut acc, w, &vec_in);
        println!("CASE 4 scalar_mul_add");
        dump_base_vec("acc", &acc);

        // --- CASE 5: geometric_accumulate(acc[8], scalars[3], points[3]) ---
        // 原地: acc[i] += sum_j scalars[j] * points[j]^i
        // 用于 WHIR 中 OOD 约束的批量累加
        let mut acc2: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let scalars: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let points: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        algebra::geometric_accumulate(&mut acc2, scalars, &points);
        println!("CASE 5 geometric_accumulate");
        dump_base_vec("acc", &acc2);
    }

    // ========================================================================
    // SECTION multilinear — 多线性多项式运算
    //
    // 测试: multilinear_extend (MLE 求值), eval_eq (相等多项式)
    //
    // multilinear_extend(evals, point):
    //   输入 evals 是布尔超立方上 2^k 个点的取值
    //   输入 point 是求值点 (k 个变量)
    //   用递归降维法在 O(2^k) 时间求值
    //
    // eval_eq(acc, point, scalar):
    //   原地: acc[i] += scalar * eq(point, i)
    //   其中 eq 是相等多项式: eq(p, q) = 1 if p==q else 0
    //
    // 对应 C++: algebra/multilinear.hpp
    // ========================================================================
    println!("# SECTION multilinear");
    {
        let mut rng = Lcg::new(0x2222_2222_2222_2222);

        // CASE 0/1/2: 分别测 k=3(8个值), k=4(16个值), k=5(32个值)
        for (case, k) in [3usize, 4, 5].iter().enumerate() {
            let n = 1usize << k;  // 2^k 个取值点
            let evals: Vec<_> = (0..n).map(|_| Field64::from(rng.next_u64())).collect();
            let point: Vec<_> = (0..*k).map(|_| Field64::from(rng.next_u64())).collect();
            println!("CASE {case} multilinear_extend k={k}");
            print_base("  result", algebra::multilinear_extend(&evals, &point));
        }

        // CASE 3: eval_eq with point of size 3 → 2^3=8 个输出
        let point3: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar3 = Field64::from(rng.next_u64());
        let mut acc3 = vec![Field64::ZERO; 8];
        algebra::eval_eq(&mut acc3, &point3, scalar3);
        println!("CASE 3 eval_eq k=3");
        dump_base_vec("acc", &acc3);

        // CASE 4: eval_eq with point of size 4 → 2^4=16 个输出
        let point4: Vec<_> = (0..4).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar4 = Field64::from(rng.next_u64());
        let mut acc4 = vec![Field64::ZERO; 16];
        algebra::eval_eq(&mut acc4, &point4, scalar4);
        println!("CASE 4 eval_eq k=4");
        dump_base_vec("acc", &acc4);
    }

    // ========================================================================
    // SECTION sumcheck — Sumcheck 协议底层函数
    //
    // compute_sumcheck_polynomial(a, b):
    //   给定两个等长向量 a, b, 计算 sumcheck 多项式系数 c0 和 c2
    //   (c1 = sum - 2*c0 - c2, 不直接计算)
    //   数学含义: 把内积 Σ a_i·b_i 压缩到单点求值
    //
    // fold(values, weight):
    //   用折叠随机性把 2n 个值压缩为 n 个: values'[i] = values[2i] + weight*(values[2i+1]-values[2i])
    //   这是 sumcheck 协议的核心归约步骤
    //
    // 对应 C++: algebra/sumcheck.hpp
    // ========================================================================
    println!("# SECTION sumcheck");
    {
        let mut rng = Lcg::new(0x3333_3333_3333_3333);

        // CASE 0/1: 长度 8 和 16 的 sumcheck 多项式
        for (case, n) in [8usize, 16].iter().enumerate() {
            let a: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            let b: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            // compute_sumcheck_polynomial 返回 (c0, c2)
            // c0 = Σ a[2i]*b[2i+1],  c2 = Σ a[2i+1]*b[2i]
            // c1 = Σ a[i]*b[i] - 2*c0 - c2
            let (acc0, acc2) = whir::algebra::sumcheck::compute_sumcheck_polynomial(&a, &b);
            println!("CASE {case} compute_sumcheck_polynomial n={n}");
            print_base("  acc0", acc0);
            print_base("  acc2", acc2);
        }

        // CASE 2: fold 16 个值 → 8 个值
        let mut values: Vec<_> = (0..16).map(|_| Field64::from(rng.next_u64())).collect();
        let weight = Field64::from(rng.next_u64());
        whir::algebra::sumcheck::fold(&mut values, weight);
        println!("CASE 2 fold n=16");
        dump_base_vec("folded", &values);
    }

    // ========================================================================
    // SECTION ntt — 数论变换 (Number Theoretic Transform)
    //
    // ntt(values): 原地 FFT 风格的快速 NTT
    //   用于 Reed-Solomon 编码 (把系数多项式转为求值点表示)
    //
    // Goldilocks 域 TWO_ADICITY=32, 支持最大 2^32 个点的 NTT
    //
    // 对应 C++: algebra/ntt/cooley_tukey.hpp
    // ========================================================================
    println!("# SECTION ntt");
    {
        let mut rng = Lcg::new(0x4444_4444_4444_4444);

        // CASE 0/1/2/3: 分别测 size = 4, 8, 16, 64
        for (case, n) in [4usize, 8, 16, 64].iter().enumerate() {
            let mut values: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            ntt::ntt(&mut values);  // 原地 NTT 变换
            println!("CASE {case} ntt n={n}");
            dump_base_vec("out", &values);
        }
    }

    // ========================================================================
    // SECTION wavelet — 小波变换
    //
    // wavelet_transform(values): 将 NTT 求值结果重组为小波基表示
    //   用于 WHIR 递归折叠中对多项式进行结构化压缩
    //
    // 对应 C++: algebra/ntt/wavelet.hpp
    // ========================================================================
    println!("# SECTION wavelet");
    {
        let mut rng = Lcg::new(0x5555_5555_5555_5555);

        // CASE 0/1: size = 8, 64
        for (case, n) in [8usize, 64].iter().enumerate() {
            let mut values: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            ntt::wavelet_transform(&mut values);
            println!("CASE {case} wavelet n={n}");
            dump_base_vec("out", &values);
        }
    }

    // ========================================================================
    // SECTION transpose — 矩阵转置
    //
    // transpose(matrix, rows, cols): 原地转置 rows×cols 矩阵
    //   用于 NTT 六步法中的矩阵转置步骤
    //   这里测试 rows=8, cols=4 的 u64 矩阵 (非域元素)
    //
    // 对应 C++: algebra/ntt/transpose.hpp
    // ========================================================================
    println!("# SECTION transpose");
    {
        let mut rng = Lcg::new(0x6666_6666_6666_6666);

        // CASE 0: 8×4 矩阵转置 → 4×8
        let rows = 8usize;
        let cols = 4usize;
        let mut m: Vec<u64> = (0..rows * cols).map(|_| rng.next_u64()).collect();
        ntt::transpose(&mut m, rows, cols);
        println!("CASE 0 transpose 8x4");
        for v in &m {
            println!("  {v}");
        }
    }

    // ========================================================================
    // SECTION linear_form — 线性形式 (LinearForm trait 的三个实现)
    //
    // LinearForm<F> 是 WHIR 中表达"线性约束"的抽象, 三个具体类型:
    //
    //   Covector<F>               — 显式向量 w, 线性泛函 ⟨w, v⟩
    //     - mle_evaluate(point)   — 对 w 做多线性扩张在 point 处求值
    //     - accumulate(acc, s)    — acc[i] += s * w[i]
    //
    //   MultilinearExtension<F>   — 固定点 p 处的 MLE 求值
    //     - mle_evaluate(point)   — 计算 eq(p, point) (相等多项式)
    //     - accumulate(acc, s)    — acc[i] += s * eq(p, i)
    //     - evaluate(emb, vec)    — 在嵌入下求值: ⟨eq_weights(p), vec⟩
    //
    //   UnivariateEvaluation<F>   — 在点 x 处做单变量求值: sum_i v_i·x^i
    //     - mle_evaluate(point)   — 把单变量求值嵌入多线性空间求值
    //     - accumulate(acc, s)    — acc[i] += s * x^i
    //     - accumulate_many(...)  — 批量版, 用 geometric_accumulate 加速
    //
    // 对应 C++: algebra/linear_form.hpp
    // ========================================================================
    println!("# SECTION linear_form");
    {
        let mut rng = Lcg::new(0x7777_7777_7777_7777);

        // --- CASE 0: Covector ---
        // 一个长度为 8 的显式线性泛函
        let cv_vec: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let cv = Covector::new(cv_vec);
        let pt3: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar = Field64::from(rng.next_u64());
        println!("CASE 0 covector");
        // trait 方法需要显式导入
        use whir::algebra::linear_form::LinearForm;
        // size() 返回布尔超立方体的大小 (8 = 2³ 个点)
        print_base("  size", Field64::from(LinearForm::size(&cv) as u64));
        // MLE 求值: 在 point (3个变量) 处
        print_base("  mle_evaluate", LinearForm::mle_evaluate(&cv, &pt3));
        // accumulate: 把标量乘结果累加到 acc
        let mut acc = vec![Field64::ZERO; 8];
        LinearForm::accumulate(&cv, &mut acc, scalar);
        dump_base_vec("accumulate", &acc);

        // --- CASE 1: MultilinearExtension ---
        // 定义在 point[3] 处的相等多项式 eq(point, ·)
        let mle_point: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let mle = MultilinearExtension::new(mle_point);
        let pt3b: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar2 = Field64::from(rng.next_u64());
        println!("CASE 1 multilinear_extension");
        print_base("  size", Field64::from(LinearForm::size(&mle) as u64));
        print_base("  mle_evaluate", LinearForm::mle_evaluate(&mle, &pt3b));
        let mut acc = vec![Field64::ZERO; 8];
        LinearForm::accumulate(&mle, &mut acc, scalar2);
        dump_base_vec("accumulate", &acc);

        // --- CASE 2: UnivariateEvaluation ---
        // 在点 x 处的单变量求值泛函: acc[i] += scalar * x^i
        let x = Field64::from(rng.next_u64());
        let ue = UnivariateEvaluation::new(x, 8);
        let pt3c: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar3 = Field64::from(rng.next_u64());
        println!("CASE 2 univariate_evaluation");
        print_base("  size", Field64::from(LinearForm::size(&ue) as u64));
        print_base("  mle_evaluate", LinearForm::mle_evaluate(&ue, &pt3c));
        let mut acc = vec![Field64::ZERO; 8];
        LinearForm::accumulate(&ue, &mut acc, scalar3);
        dump_base_vec("accumulate", &acc);

        // --- CASE 3: accumulate_many ---
        // 3 个 UnivariateEvaluation, 不同求值点, 批量累加到同一个 acc[8]
        let evaluators: Vec<_> = (0..3)
            .map(|_| UnivariateEvaluation::new(Field64::from(rng.next_u64()), 8))
            .collect();
        let scalars: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let mut acc = vec![Field64::ZERO; 8];
        UnivariateEvaluation::accumulate_many(&evaluators, &mut acc, &scalars);
        println!("CASE 3 univariate_accumulate_many");
        dump_base_vec("acc", &acc);
    }

    // ========================================================================
    // SECTION utils — 通用工具函数
    //
    // base_decomposition(value, base, n_bits):
    //   把 value 按 base 进制分解为 n_bits 个数字
    //   用固定测试用例 (不依赖随机数)
    //
    // expand_randomness(base, length):
    //   等价于 geometric_sequence — 产生 [1, base, base², ...]
    //
    // 对应 C++: utils.hpp
    // ========================================================================
    println!("# SECTION utils");
    {
        // --- CASE 0-7: base_decomposition ---
        // 固定用例, 覆盖: 小值、零值、大底数、多位数
        let cases: &[(usize, u8, usize)] = &[
            (0b1011, 2, 6),   // 值=11,  二进制, 6位
            (5, 2, 4),         // 值=5,   二进制, 4位
            (10, 2, 4),        // 值=10,  二进制, 4位
            (0, 2, 4),         // 值=0,   二进制, 4位
            (15, 3, 3),        // 值=15,  三进制, 3位
            (8, 3, 4),         // 值=8,   三进制, 4位
            (123, 5, 4),       // 值=123, 五进制, 4位
            (100, 7, 5),       // 值=100, 七进制, 5位
        ];
        for (case_idx, &(value, base, n_bits)) in cases.iter().enumerate() {
            let digits = base_decomposition(value, base, n_bits);
            println!("CASE {case_idx} base_decomposition v={value} b={base} n={n_bits}");
            print!("  digits");
            for d in &digits { print!(" {d}"); }
            println!();
        }

        // --- CASE 8: expand_randomness — 和 geometric_sequence 等价 ---
        let mut rng = Lcg::new(0x9999_9999_9999_9999);
        let base = Field64::from(rng.next_u64());
        let seq = expand_randomness(base, 6);
        println!("CASE 8 expand_randomness");
        dump_base_vec("seq", &seq);
    }

    // ========================================================================
    // SECTION hash — 哈希引擎测试
    //
    // 测试三种 HashEngine 的 hash_many 输出:
    //   COPY:   恒等映射 (前 32 字节 = 输入, 用于测试)
    //   BLAKE3: 64B 对齐输入, 高性能批哈希
    //   SHA2:   任意大小输入, SHA-256
    //
    // 每个 CASE 输出 count 个 32 字节哈希值 (16进制)
    //
    // 对应 C++: hash/sha2_engine.hpp, hash/blake3_engine.hpp, hash/copy_engine.hpp
    // ========================================================================
    println!("# SECTION hash");
    {
        let mut rng = Lcg::new(0xAAAA_AAAA_AAAA_AAAA);

        // 打印哈希值为 64 位十六进制字符串
        let print_hash = |label: &str, h: &Hash| {
            print!("  {label} ");
            for byte in h.0.iter() {
                print!("{byte:02x}");
            }
            println!();
        };

        // 从 LCG 取 n 字节确定性输入
        let make_bytes = |rng: &mut Lcg, n: usize| -> Vec<u8> {
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                let w = rng.next_u64().to_le_bytes();
                for &b in &w {
                    if v.len() < n { v.push(b); }
                }
            }
            v
        };

        // 通用哈希测试闭包: 用指定引擎, 输入 size*count 字节, 输出 count 个哈希
        let run = |rng: &mut Lcg, case: usize, engine_id: EngineId, label: &str,
                   size: usize, count: usize| {
            let engine = ENGINES.retrieve(engine_id).expect("engine missing");
            let input = make_bytes(rng, size * count);
            let mut output = vec![Hash::default(); count];
            // hash_many: 把 input 切成 count 段, 每段 size 字节, 分别哈希
            engine.hash_many(size, &input, &mut output);
            println!("CASE {case} {label} size={size} count={count}");
            for (i, h) in output.iter().enumerate() {
                print_hash(&format!("h{i}"), h);
            }
        };

        // Copy 引擎: 恒等映射
        run(&mut rng, 0, COPY, "copy", 0, 2);
        run(&mut rng, 1, COPY, "copy", 16, 2);
        run(&mut rng, 2, COPY, "copy", 32, 3);

        // BLAKE3 引擎: 需要 size 是 64 的倍数
        run(&mut rng, 3, BLAKE3, "blake3", 64, 1);
        run(&mut rng, 4, BLAKE3, "blake3", 64, 4);
        run(&mut rng, 5, BLAKE3, "blake3", 128, 2);
        run(&mut rng, 6, BLAKE3, "blake3", 256, 1);
        run(&mut rng, 7, BLAKE3, "blake3", 1024, 1);

        // SHA-2 引擎: 任意大小
        run(&mut rng, 8, SHA2, "sha2", 0, 1);
        run(&mut rng, 9, SHA2, "sha2", 31, 1);
        run(&mut rng, 10, SHA2, "sha2", 32, 3);
        run(&mut rng, 11, SHA2, "sha2", 64, 2);
        run(&mut rng, 12, SHA2, "sha2", 100, 2);
    }

    // ========================================================================
    // SECTION merkle_tree — Merkle 树纯算法测试
    //
    // 内联实现 (不依赖 transcript):
    //   build_tree(hash_id, num_leaves, leaves) → 完整树节点数组
    //   open_path(num_leaves, witness, indices)  → sibling hint 列表
    //
    // 采样 3 组: BLAKE3-16叶, BLAKE3-32叶, SHA2-8叶
    //
    // 对应 C++: protocols/merkle_tree.hpp
    // ========================================================================

    // 计算 num_leaves 个叶子需要的层数 = ceil(log2(num_leaves))
    fn layers_for_size(size: usize) -> usize {
        if size <= 1 { return 0; }
        let mut p = 1usize; let mut k = 0usize;
        while p < size { p <<= 1; k += 1; }
        k
    }

    // 自底向上构建 Merkle 树
    // 返回所有节点 (叶子层在最前, 根在最后), 布局和 C++ merkle_tree::build_tree 一致
    fn build_tree(hash_id: EngineId, num_leaves: usize, leaves: Vec<Hash>) -> Vec<Hash> {
        let layers = layers_for_size(num_leaves);
        let leaf_layer = 1usize << layers;      // 叶子层补齐到 2 的幂
        let total = (1usize << (layers + 1)) - 1; // 完全二叉树节点总数
        let mut nodes = leaves;
        nodes.resize(total, Hash::default());   // 零填充到总节点数

        let engine = ENGINES.retrieve(hash_id).expect("engine");
        let mut prev_off = 0usize;       // 上一层在 nodes 数组中的起始位置
        let mut prev_len = leaf_layer;   // 上一层长度
        let mut curr_off = leaf_layer;   // 当前层起始位置

        // 从叶子往上逐层哈希
        for _ in 0..layers {
            let curr_len = prev_len / 2;  // 每层长度减半

            // hash_many: 每对相邻节点 (64 字节) → 父节点 (32 字节)
            let (head, tail) = nodes.split_at_mut(curr_off);
            let prev_slice: &[Hash] = &head[prev_off..prev_off + prev_len];
            let curr_slice: &mut [Hash] = &mut tail[..curr_len];
            engine.hash_many(64, prev_slice.as_bytes(), curr_slice);

            prev_off = curr_off;
            prev_len = curr_len;
            curr_off += curr_len;
        }
        nodes
    }

    // 打开 Merkle 路径: 返回 sorted + deduped indices 的 sibling hint
    fn open_path(num_leaves: usize, witness: &[Hash], indices: &[usize]) -> Vec<Hash> {
        let layers = layers_for_size(num_leaves);
        let mut idx: Vec<usize> = indices.to_vec();
        idx.sort_unstable();   // 排序 + 去重
        idx.dedup();
        let mut hints = Vec::new();
        let mut layer_off = 0usize;
        let mut layer_len = 1usize << layers;
        // 自底向上: 每一层, 对于每个 index, 如果它的 sibling 不在列表里就加入 hint
        while layer_len > 1 {
            let mut next = Vec::with_capacity(idx.len());
            let mut k = 0usize;
            while k < idx.len() {
                let a = idx[k];
                // 如果 a 和 a^1 (a 的 sibling) 都在列表中 → 合并到父层, 不需要 hint
                if k + 1 < idx.len() && idx[k + 1] == (a ^ 1) {
                    next.push(a >> 1);
                    k += 2;
                } else {
                    // sibling 不在列表中 → 加入 hint
                    hints.push(witness[layer_off + (a ^ 1)]);
                    next.push(a >> 1);
                    k += 1;
                }
            }
            idx = next;
            layer_off += layer_len;
            layer_len /= 2;
        }
        hints
    }

    // 哈希打印闭包
    let dump_hash = |label: &str, h: &Hash| {
        print!("  {label} ");
        for byte in h.0.iter() {
            print!("{byte:02x}");
        }
        println!();
    };

    println!("# SECTION merkle_tree");
    {
        // 测试用例: (标签, hash引擎, 叶子数, 打开的索引)
        let cases: &[(&str, EngineId, usize, &[usize])] = &[
            ("blake3-16-2",  BLAKE3, 16, &[3, 5, 11]),
            ("blake3-32-3",  BLAKE3, 32, &[0, 1, 2, 31]),
            ("sha2-8-2",    SHA2,    8, &[2, 6]),
        ];
        for (case_idx, &(label, hash_id, num_leaves, indices)) in cases.iter().enumerate() {
            // 生成确定性叶子: leaf[i] 的 32 字节用规则模式填充
            let leaves: Vec<Hash> = (0..num_leaves)
                .map(|i| {
                    let mut h = [0u8; 32];
                    for (j, b) in h.iter_mut().enumerate() {
                        *b = ((i * 31 + j) & 0xFF) as u8;
                    }
                    Hash(h)
                })
                .collect();

            let witness = build_tree(hash_id, num_leaves, leaves);
            let layers = layers_for_size(num_leaves);
            let leaf_layer = 1usize << layers;
            let total = (1usize << (layers + 1)) - 1;
            let root = witness[total - 1];      // 根在最后一棵树节点数组的最后一个位置
            let hints = open_path(num_leaves, &witness, indices);

            println!("CASE {case_idx} {label} num_leaves={num_leaves}");
            dump_hash("root", &root);
            println!("  leaf_layer {leaf_layer}");
            println!("  num_hints {}", hints.len());
            for (i, h) in hints.iter().enumerate() {
                dump_hash(&format!("hint{i}"), h);
            }
        }
    }

    // ========================================================================
    // SECTION pow — Proof of Work 测试
    //
    // 难度 threshold = 2^60 (4 bit 难度, 单批就能找到 nonce)
    // 算法: hash(challenge[32B] || nonce_le[8B] || zeros[24B]) 的前 8 字节
    //       解释为 little-endian u64, 要求 <= threshold
    //
    // 对应 C++: protocols/proof_of_work.hpp
    // ========================================================================
    println!("# SECTION pow");
    {
        let cases: &[(&str, EngineId, u64, [u8; 32])] = &[
            ("blake3-thr60bits", BLAKE3, 1u64 << 60, [0xAA; 32]),
            ("sha2-thr60bits",   SHA2,   1u64 << 60, [0x55; 32]),
        ];
        for (case_idx, &(label, hash_id, threshold, challenge)) in cases.iter().enumerate() {
            let engine = ENGINES.retrieve(hash_id).expect("engine");

            // 批处理查找最小 nonce (和 C++ 端的 find_nonce 逻辑一致)
            let batch = engine.preferred_batch_size().max(1);
            let mut inputs = vec![[0u8; 64]; batch];
            for inp in &mut inputs { inp[..32].copy_from_slice(&challenge); }
            let mut outputs = vec![Hash::default(); batch];
            let mut found_nonce: Option<u64> = None;

            'outer: for base in (0u64..).step_by(batch) {
                for (i, inp) in inputs.iter_mut().enumerate() {
                    let n = base + i as u64;
                    inp[32..40].copy_from_slice(&n.to_le_bytes());
                }
                engine.hash_many(64, inputs.as_bytes(), &mut outputs);
                for (i, out) in outputs.iter().enumerate() {
                    let v = u64::from_le_bytes(out.0[..8].try_into().unwrap());
                    if v <= threshold {
                        found_nonce = Some(base + i as u64);
                        break 'outer;
                    }
                }
            }
            let nonce = found_nonce.expect("PoW must find a nonce");

            // 再哈希一次得到正式输出 (用于对拍验证)
            let mut single = [0u8; 64];
            single[..32].copy_from_slice(&challenge);
            single[32..40].copy_from_slice(&nonce.to_le_bytes());
            let mut single_out = [Hash::default(); 1];
            engine.hash_many(64, &single, &mut single_out);

            println!("CASE {case_idx} {label} threshold={threshold}");
            println!("  nonce {nonce}");
            dump_hash("hash", &single_out[0]);
        }
    }

    // ========================================================================
    // SECTION matrix_commit — 矩阵承诺的纯函数层
    //
    // 对矩阵的每一行做域元素 LE 编码 + 哈希, 得到叶子哈希列表
    // 这是 Merkle 树构建的前置步骤 (把域元素矩阵变成字节哈希叶子)
    //
    // 测试 5 组: 不同域 × 不同引擎 × 不同尺寸
    //
    // 对应 C++: protocols/matrix_commit.hpp 的 commit_leaves()
    // ========================================================================
    println!("# SECTION matrix_commit");
    {
        let mut rng = Lcg::new(0xBBBB_BBBB_BBBB_BBBB);

        // --- CASE 0: Field64, Blake3, 4 rows × 8 cols ---
        // msg_size = 8*8 = 64 (BLAKE3 要求 64 的倍数, 满足)
        {
            let num_rows = 4usize; let num_cols = 8usize;
            let msg_size = Field64::encoded_size() * num_cols; // = 64
            let total = num_rows * num_cols;
            let matrix: Vec<Field64> = (0..total).map(|_| Field64::from(rng.next_u64())).collect();
            let mut encoder = Field64::encoder();
            let bytes = encoder.encode(&matrix);
            let engine = ENGINES.retrieve(BLAKE3).expect("engine");
            let mut leaves = vec![Hash::default(); num_rows];
            engine.hash_many(msg_size, bytes, &mut leaves);
            println!("CASE 0 field64-blake3 rows={num_rows} cols={num_cols} msg_size={msg_size}");
            for (i, h) in leaves.iter().enumerate() {
                dump_hash(&format!("leaf{i}"), h);
            }
        }

        // --- CASE 1: Field64_2, Blake3, 2 rows × 8 cols ---
        // msg_size = 16*8 = 128
        {
            let num_rows = 2usize; let num_cols = 8usize;
            let msg_size = Field64_2::encoded_size() * num_cols; // = 128
            let total = num_rows * num_cols;
            let matrix: Vec<Field64_2> = (0..total)
                .map(|_| Field64_2::new(Field64::from(rng.next_u64()), Field64::from(rng.next_u64())))
                .collect();
            let mut encoder = Field64_2::encoder();
            let bytes = encoder.encode(&matrix);
            let engine = ENGINES.retrieve(BLAKE3).expect("engine");
            let mut leaves = vec![Hash::default(); num_rows];
            engine.hash_many(msg_size, bytes, &mut leaves);
            println!("CASE 1 field64_2-blake3 rows={num_rows} cols={num_cols} msg_size={msg_size}");
            for (i, h) in leaves.iter().enumerate() {
                dump_hash(&format!("leaf{i}"), h);
            }
        }

        // --- CASE 2: Field64_3, Sha2, 3 rows × 5 cols ---
        // msg_size = 24*5 = 120 (SHA-2 支持任意大小)
        {
            let num_rows = 3usize; let num_cols = 5usize;
            let msg_size = Field64_3::encoded_size() * num_cols; // = 120
            let total = num_rows * num_cols;
            let matrix: Vec<Field64_3> = (0..total)
                .map(|_| Field64_3::new(
                    Field64::from(rng.next_u64()), Field64::from(rng.next_u64()), Field64::from(rng.next_u64())))
                .collect();
            let mut encoder = Field64_3::encoder();
            let bytes = encoder.encode(&matrix);
            let engine = ENGINES.retrieve(SHA2).expect("engine");
            let mut leaves = vec![Hash::default(); num_rows];
            engine.hash_many(msg_size, bytes, &mut leaves);
            println!("CASE 2 field64_3-sha2 rows={num_rows} cols={num_cols} msg_size={msg_size}");
            for (i, h) in leaves.iter().enumerate() {
                dump_hash(&format!("leaf{i}"), h);
            }
        }

        // --- CASE 3: Field64, Sha2, 2 rows × 4 cols ---
        // msg_size = 8*4 = 32
        {
            let num_rows = 2usize; let num_cols = 4usize;
            let msg_size = Field64::encoded_size() * num_cols; // = 32
            let total = num_rows * num_cols;
            let matrix: Vec<Field64> = (0..total).map(|_| Field64::from(rng.next_u64())).collect();
            let mut encoder = Field64::encoder();
            let bytes = encoder.encode(&matrix);
            let engine = ENGINES.retrieve(SHA2).expect("engine");
            let mut leaves = vec![Hash::default(); num_rows];
            engine.hash_many(msg_size, bytes, &mut leaves);
            println!("CASE 3 field64-sha2 rows={num_rows} cols={num_cols} msg_size={msg_size}");
            for (i, h) in leaves.iter().enumerate() {
                dump_hash(&format!("leaf{i}"), h);
            }
        }

        // --- CASE 4: Field64, Copy, 3 rows × 4 cols ---
        // Copy 引擎: 恒等映射, msg_size 必须 ≤ 32
        {
            let num_rows = 3usize; let num_cols = 4usize;
            let msg_size = Field64::encoded_size() * num_cols; // = 32
            let total = num_rows * num_cols;
            let matrix: Vec<Field64> = (0..total).map(|_| Field64::from(rng.next_u64())).collect();
            let mut encoder = Field64::encoder();
            let bytes = encoder.encode(&matrix);
            let engine = ENGINES.retrieve(COPY).expect("engine");
            let mut leaves = vec![Hash::default(); num_rows];
            engine.hash_many(msg_size, bytes, &mut leaves);
            println!("CASE 4 field64-copy rows={num_rows} cols={num_cols} msg_size={msg_size}");
            for (i, h) in leaves.iter().enumerate() {
                dump_hash(&format!("leaf{i}"), h);
            }
        }
    }

    // ========================================================================
    // SECTION challenge_indices — 域内挑战索引生成
    //
    // 纯函数层 (不依赖 transcript): entropy bytes → challenge indices
    //
    // 算法:
    //   - count == 0 → 空
    //   - num_leaves == 1 → 全是 0
    //   - 否则: size_bytes = ceil(log2(num_leaves)/8)
    //     entropy 切成 count 段, 每段 size_bytes 字节按大端解析
    //     然后 mod num_leaves
    //   - dedup: 排序去重
    //
    // 对应 C++: protocols/challenge_indices.hpp 的 indices_from_entropy()
    // ========================================================================
    println!("# SECTION challenge_indices");
    {
        fn from_entropy(entropy: &[u8], num_leaves: usize, count: usize, dedup: bool) -> Vec<usize> {
            if count == 0 { return Vec::new(); }
            assert!(num_leaves.is_power_of_two());
            if num_leaves == 1 {
                return if dedup { vec![0] } else { vec![0; count] };
            }
            let size_bytes = (num_leaves.ilog2() as usize).div_ceil(8);
            assert_eq!(entropy.len(), count * size_bytes);
            let mut indices: Vec<usize> = entropy
                .chunks_exact(size_bytes)
                .map(|chunk| chunk.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize) % num_leaves)
                .collect();
            if dedup { indices.sort_unstable(); indices.dedup(); }
            indices
        }

        // 测试用例: (标签, 叶数, 挑战数, 去重, entropy字节)
        let cases: &[(&str, usize, usize, bool, &[u8])] = &[
            ("128-5-dedup",     128,        5, true,  &[0x01,0x23,0x45,0x67,0x89]),
            ("128-5-nodedup",   128,        5, false, &[0x01,0x23,0x45,0x67,0x89]),
            ("8192-5-dedup",    8192,       5, true,  &[0x01,0x23, 0x45,0x67, 0x89,0xAB, 0xCD,0xEF, 0x12,0x34]),
            ("1m-4-dedup",      1usize<<20, 4, true,  &[0x12,0x34,0x56, 0x78,0x9A,0xBC, 0xDE,0xF0,0x11, 0x22,0x33,0x44]),
            ("128-5-dups",      128,        5, true,  &[0x20,0x40,0x20,0x60,0x40]),   // 故意有重复的 entropy
            ("1leaf-3-dedup",   1,          3, true,  &[]),
            ("1leaf-3-nodedup", 1,          3, false, &[]),
            ("0count",          8,          0, true,  &[]),
        ];
        for (case_idx, &(label, num_leaves, count, dedup, entropy)) in cases.iter().enumerate() {
            let result = from_entropy(entropy, num_leaves, count, dedup);
            println!(
                "CASE {case_idx} {label} num_leaves={num_leaves} count={count} dedup={dedup} entropy_len={}",
                entropy.len()
            );
            print!("  indices");
            for v in &result { print!(" {v}"); }
            println!();
        }
    }
}
