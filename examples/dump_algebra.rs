// ===========================================================================
// dump_algebra.rs — 代数工具 golden test。
//
// 运行: cargo run --example dump_algebra --release > golden_algebra_rs.txt
// 覆盖: utilities (几何序列/内积/张量积/标量乘加/几何累加) +
//       multilinear (MLE 求值/eval_eq) +
//       sumcheck (多项式计算/fold) +
//       linear_form (Covector/MLE/UnivariateEvaluation) +
//       utils (base_decomposition/expand_randomness)
// ===========================================================================

use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use whir::algebra::fields::{Field64, Field64_2, Field64_3};
use whir::algebra::{
    self,
    linear_form::{Covector, MultilinearExtension, UnivariateEvaluation},
    ntt,
};
use whir::utils::{base_decomposition, expand_randomness};

// ===========================================================================
// LCG — 与 C++ 侧完全一致
// ===========================================================================
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

fn print_base(label: &str, a: Field64) {
    let v: u64 = a.into_bigint().0[0];
    println!("{label} {v}");
}

fn main() {
    // 向量打印闭包
    let dump_base_vec = |label: &str, v: &[Field64]| {
        println!("  {label} {}", v.len());
        for x in v { print_base("    ", *x); }
    };

    // ========================================================================
    // SECTION utilities — 代数工具函数 (seed: 0x1111...)
    // ========================================================================
    println!("# SECTION utilities");
    {
        let mut rng = Lcg::new(0x1111_1111_1111_1111);

        // geometric_sequence(base, 8)
        let base = Field64::from(rng.next_u64());
        println!("CASE 0 geometric_sequence");
        let seq = algebra::geometric_sequence(base, 8);
        dump_base_vec("seq", &seq);

        // dot(a[8], b[8])
        let a: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let b: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        println!("CASE 1 dot");
        print_base("  result", algebra::dot(&a, &b));

        // tensor_product(a[3], b[2])
        let aa: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let bb: Vec<_> = (0..2).map(|_| Field64::from(rng.next_u64())).collect();
        println!("CASE 2 tensor_product");
        let tp = algebra::tensor_product(&aa, &bb);
        dump_base_vec("tp", &tp);

        // univariate_evaluate(coeffs[8], x)
        let coeffs: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let x = Field64::from(rng.next_u64());
        println!("CASE 3 univariate_evaluate");
        print_base("  result", algebra::univariate_evaluate(&coeffs, x));

        // scalar_mul_add(acc[8], w, vec[8])
        let mut acc: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let w = Field64::from(rng.next_u64());
        let vec_in: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        algebra::scalar_mul_add(&mut acc, w, &vec_in);
        println!("CASE 4 scalar_mul_add");
        dump_base_vec("acc", &acc);

        // geometric_accumulate(acc[8], scalars[3], points[3])
        let mut acc2: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let scalars: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let points: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        algebra::geometric_accumulate(&mut acc2, scalars, &points);
        println!("CASE 5 geometric_accumulate");
        dump_base_vec("acc", &acc2);
    }

    // ========================================================================
    // SECTION multilinear — 多线性多项式 (seed: 0x2222...)
    // ========================================================================
    println!("# SECTION multilinear");
    {
        let mut rng = Lcg::new(0x2222_2222_2222_2222);

        for (case, k) in [3usize, 4, 5].iter().enumerate() {
            let n = 1usize << k;
            let evals: Vec<_> = (0..n).map(|_| Field64::from(rng.next_u64())).collect();
            let point: Vec<_> = (0..*k).map(|_| Field64::from(rng.next_u64())).collect();
            println!("CASE {case} multilinear_extend k={k}");
            print_base("  result", algebra::multilinear_extend(&evals, &point));
        }

        // eval_eq k=3
        let point3: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar3 = Field64::from(rng.next_u64());
        let mut acc3 = vec![Field64::ZERO; 8];
        algebra::eval_eq(&mut acc3, &point3, scalar3);
        println!("CASE 3 eval_eq k=3");
        dump_base_vec("acc", &acc3);

        // eval_eq k=4
        let point4: Vec<_> = (0..4).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar4 = Field64::from(rng.next_u64());
        let mut acc4 = vec![Field64::ZERO; 16];
        algebra::eval_eq(&mut acc4, &point4, scalar4);
        println!("CASE 4 eval_eq k=4");
        dump_base_vec("acc", &acc4);
    }

    // ========================================================================
    // SECTION sumcheck — 多项式折叠 (seed: 0x3333...)
    // ========================================================================
    println!("# SECTION sumcheck");
    {
        let mut rng = Lcg::new(0x3333_3333_3333_3333);

        for (case, n) in [8usize, 16].iter().enumerate() {
            let a: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            let b: Vec<_> = (0..*n).map(|_| Field64::from(rng.next_u64())).collect();
            let (acc0, acc2) = whir::algebra::sumcheck::compute_sumcheck_polynomial(&a, &b);
            println!("CASE {case} compute_sumcheck_polynomial n={n}");
            print_base("  acc0", acc0);
            print_base("  acc2", acc2);
        }

        let mut values: Vec<_> = (0..16).map(|_| Field64::from(rng.next_u64())).collect();
        let weight = Field64::from(rng.next_u64());
        whir::algebra::sumcheck::fold(&mut values, weight);
        println!("CASE 2 fold n=16");
        dump_base_vec("folded", &values);
    }

    // ========================================================================
    // SECTION linear_form — 线性形式 (seed: 0x7777...)
    // ========================================================================
    println!("# SECTION linear_form");
    {
        let mut rng = Lcg::new(0x7777_7777_7777_7777);
        use whir::algebra::linear_form::LinearForm;

        // Covector
        let cv_vec: Vec<_> = (0..8).map(|_| Field64::from(rng.next_u64())).collect();
        let cv = Covector::new(cv_vec);
        let pt3: Vec<_> = (0..3).map(|_| Field64::from(rng.next_u64())).collect();
        let scalar = Field64::from(rng.next_u64());
        println!("CASE 0 covector");
        print_base("  size", Field64::from(LinearForm::size(&cv) as u64));
        print_base("  mle_evaluate", LinearForm::mle_evaluate(&cv, &pt3));
        let mut acc = vec![Field64::ZERO; 8];
        LinearForm::accumulate(&cv, &mut acc, scalar);
        dump_base_vec("accumulate", &acc);

        // MultilinearExtension
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

        // UnivariateEvaluation
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

        // accumulate_many
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
    // SECTION utils — 通用工具 (seed: 0x9999...)
    // ========================================================================
    println!("# SECTION utils");
    {
        // base_decomposition (固定用例)
        let cases: &[(usize, u8, usize)] = &[
            (0b1011, 2, 6), (5, 2, 4), (10, 2, 4), (0, 2, 4),
            (15, 3, 3), (8, 3, 4), (123, 5, 4), (100, 7, 5),
        ];
        for (case_idx, &(value, base, n_bits)) in cases.iter().enumerate() {
            let digits = base_decomposition(value, base, n_bits);
            println!("CASE {case_idx} base_decomposition v={value} b={base} n={n_bits}");
            print!("  digits");
            for d in &digits { print!(" {d}"); }
            println!();
        }

        let mut rng = Lcg::new(0x9999_9999_9999_9999);
        let base = Field64::from(rng.next_u64());
        let seq = expand_randomness(base, 6);
        println!("CASE 8 expand_randomness");
        dump_base_vec("seq", &seq);
    }
}
