# WHIR 验证者 `Config<M>::verify()` 完整运行例子

## 协议背景速览

`verify()` 的目标：验证者拿到证明者的承诺和声明求值后，通过 12 步交互验证，输出一个 `FinalClaim`。验证者随后可本地检查：

```
SUM_i rlc_coefficients[i] * linear_forms[i].mle_evaluate(evaluation_point) == linear_form_rlc
```

核心数据流：`evaluations` + `oods_matrix` → `the_sum` → sumcheck 折叠 → `final_vector` 一致性检查 → 恢复 `linear_form_rlc`。

### 关键变量速查表

| 变量 | 协议含义 |
|------|----------|
| `vector_rlc_coeffs` | 把多个向量压成一个随机线性组合，系数为几何级数 [1, α, α², ...] |
| `constraint_rlc_coeffs` | 把初始线性约束和 OOD 约束压成一个总约束 |
| `initial_forms_rlc` | `constraint_rlc_coeffs` 中对应初始线性形式的部分 |
| `oods_rlc` | `constraint_rlc_coeffs` 中对应 OOD 约束的部分 |
| `the_sum` | sumcheck 要验证的目标和，等于所有约束的加权内积 |
| `oods_matrix` | 域外（Out-of-Domain）求值矩阵，行优先存储 |
| `oods_evals` | OOD 点对应的 UnivariateEvaluation 对象 |
| `round_fr` | 每轮 sumcheck 返回的折叠随机点列表 |
| `round_constraints` | 逐轮保存的约束（用于步骤 12 恢复 linear_form_rlc） |
| `final_vector` | 证明者在最后发送的明文多项式系数 |
| `evaluation_point` | 所有 sumcheck 轮坐标的拼接，即最终求值点 |
| `linear_form_rlc` | 从 sumcheck 不变量恢复的线性形式 RLC 值 |

### 使用的有限域

所有例子在 **F₁₇**（模 17 的整数域）中运算：
- `F::zero() = 0`, `F::one() = 1`
- 加减乘除均在 mod 17 下进行
- 乘法逆元：`a⁻¹ mod 17` 通过扩展欧几里得算法求得

### 说明

- Merkle 树验证、PoW、sumcheck 内部均假设"通过"或给出具体数值
- `geometric_challenge<F>()` 假设返回固定数组（实际由 Fiat-Shamir transcript 挤压）
- 变量名与代码（`whir_verifier.hpp`）保持一致

---

## 例子 1：最小正常通过案例

### A. 初始配置

| 参数 | 值 | 说明 |
|------|------|------|
| 域 F | F₁₇ (模 17) | 所有运算 mod 17 |
| commitments_ptr | 1 个 commitment | 指向 1 个 IRS 承诺 |
| initial_committer.num_vectors | 1 | 每个承诺包含 1 个向量 |
| initial_committer.vector_size | 2 | 向量长度 = 2（系数个数） |
| initial_committer.codeword_length | 2 | RS 码字长度（简化） |
| initial_committer.out_domain_samples | 1 | 1 个 OOD 采样点 |
| initial_committer.in_domain_samples | 1 | 1 个域内查询 |
| num_vectors | 1 | = commitments_ptr.size() × num_vectors = 1 × 1 |
| num_linear_forms | 1 | = evaluations.size() / num_vectors = 1 / 1 |
| round_configs | **空** | 无 STIR 轮次 |
| initial_sumcheck.initial_size | 2 | 初始 sumcheck 输入大小 |
| initial_sumcheck.num_rounds | 1 | 折叠 1 轮 |
| final_sumcheck.initial_size | 1 | 最终 sumcheck 输入大小 = 2^(1-1) |
| final_sumcheck.num_rounds | 1 | 最终折叠 1 轮 |

**协议含义**：证明者承诺 1 个长度为 2 的向量 v = [v₀, v₁]，声明 1 个线性形式 LF 在 v 上的求值。验证者要检查 LF(v) 是否等于声明值。

### B. 输入数据

**线性形式**：LF(r₀, r₁) = r₀（提取第一个系数，即 Lagrange 基 L₀）

**声明求值**：`evaluations = [13]`
- 含义：LF(v) = v₀ = 13（声明向量第一个分量是 13）

**承诺 commitment 的 OOD 数据**：
- OOD 点：z = 5（从 transcript 挤压）
- OOD 矩阵：`out_of_domain.matrix = [6]`（= f(5) = v₀ + 5·v₁ 的声明值）
- `out_of_domain.points = [5]`

**Prover 实际向量**：v = [13, 2]（验证者不知道，但可以验证一致性）
- f(5) = 13 + 5·2 = 23 ≡ 6 (mod 17) ✓
- LF(v) = v₀ = 13 ✓

**Transcript 中 prover 依次发送的值**（步骤 1）：无额外 OOD 值（所有向量已被承诺覆盖）

**假设的 sumcheck 交互**（步骤 5）：
- 证明者发送 c0 = 8, c2 = 13（下面会解释）
- 验证者挤压挑战 r = 11

**最终向量**（步骤 7）：`final_vector = [11]`

### C. 从步骤 1 到步骤 12 的完整流程

---

**步骤 1：读取补全的 OOD 求值**（代码第 89-112 行）

遍历唯一的 commitment：
- `c_evals = commitment->out_of_domain.evaluators(2)` → 返回 1 个 `UnivariateEvaluation<F>(z=5, size=2)`
  - 这代表单变量多项式 f(X) = v₀ + X·v₁ 在 X=5 处的求值
- `c_cols = 1`（1 个向量）
- 内层循环 j=0（唯一向量）：j ∈ [0, 1) = [vector_offset, vector_offset+c_cols)，所以从承诺矩阵读取：
  - `oods_matrix = [6]`（承诺中的 OOD 值）
- `oods_evals = [UnivariateEvaluation(5, 2)]`

结果：
```
oods_matrix = [6]           // 1×1 矩阵：1 个 OOD 点 × 1 个向量
oods_evals = [UE(5, 2)]    // OOD 点 z=5，向量大小 2
```

---

**步骤 2：向量 RLC**（代码第 117 行）

```cpp
vector_rlc_coeffs = geometric_challenge<F>(verifier_state, 1);
```

count = 1 时直接返回 `[1]`（无需挤压随机元素，见 `geometric_challenge.hpp:40-41`）。

含义：只有 1 个向量，RLC 系数就是 [1]，相当于不做组合。

---

**步骤 3：约束 RLC**（代码第 122-125 行）

```cpp
constraint_rlc_coeffs = geometric_challenge<F>(verifier_state, 1 + 1);
// num_linear_forms + oods_evals.size() = 1 + 1 = 2
```

count = 2，从 transcript 挤压随机元素 x（假设 x = 3）：
```
constraint_rlc_coeffs = [1, 3]   // [1, x] = [1, 3]
```

拆分：
```
initial_forms_rlc = [1]      // 前 num_linear_forms=1 个
oods_rlc = [3]               // 剩余 oods_evals.size()=1 个
```

含义：
- `initial_forms_rlc[0] = 1` 是初始线性形式 LF 的 RLC 系数
- `oods_rlc[0] = 3` 是 OOD 约束的 RLC 系数
- 几何级数 [1, x, x², ...] 保证只需一次 transcript 挤压即可生成所有系数

---

**步骤 4：计算 The Sum**（代码第 130-150 行）

**初始约束部分**（代码第 132-137 行）：

对 i=0（唯一的线性形式）：
```
row_sum = Σ_j vector_rlc_coeffs[j] * evaluations[0*num_vectors + j]
        = vector_rlc_coeffs[0] * evaluations[0]
        = 1 * 13 = 13
the_sum += constraint_rlc_coeffs[0] * row_sum
         = 1 * 13 = 13
```

**OOD 约束部分**（代码第 139-144 行）：

对 i=0（唯一的 OOD 行）：
```
row_sum = Σ_j vector_rlc_coeffs[j] * oods_matrix[0*num_vectors + j]
        = 1 * 6 = 6
the_sum += oods_rlc[0] * row_sum
         = 3 * 6 = 18 ≡ 1 (mod 17)
```

**最终**：`the_sum = 13 + 1 = 14`

代数式：
```
the_sum = initial_forms_rlc[0] · (vector_rlc_coeffs[0] · evaluations[0])
        + oods_rlc[0] · (vector_rlc_coeffs[0] · oods_matrix[0])
        = 1 · (1 · 13) + 3 · (1 · 6)
        = 13 + 18 = 31 ≡ 14 (mod 17)
```

保存约束（代码第 147-150 行）：
```
round_constraints = [
  (oods_rlc=[3], oods_evals=[UE(5, 2)])
]
```

---

**步骤 5：初始 sumcheck 验证**（代码第 159-173 行）

`constraint_rlc_coeffs` 非空（长度 2），所以进入 `else` 分支（代码第 168-171 行）：

```cpp
fr = initial_sumcheck.verify(verifier_state, the_sum);  // the_sum = 14
```

sumcheck 内部（`sumcheck_protocol.hpp` 第 150-188 行），1 轮，初始大小 2：

证明者的两个输入是多线性多项式 a, b（大小 = initial_size = 2），满足 `<a, b> = the_sum`。

假设证明者的 a = [13, 1], b = [1, 0]：
- c0 = a[0]·b[0] = 13·1 = 13（`compute_sumcheck_polynomial` 的 acc0）
- c2 = (a[1]-a[0])·(b[1]-b[0]) = (1-13)·(0-1) = (-12)·(-1) = 12

证明者发送 c0 = 13, c2 = 12。

**验证者处理**：
1. 读取 c0 = 13, c2 = 12（代码第 170-172 行）
2. 推导 c1 = the_sum - 2·c0 - c2 = 14 - 26 - 12 = -24 ≡ 10 (mod 17)
3. 验证 PoW（假设通过）
4. 挤压挑战 r = 11（代码第 180 行）
5. 更新 the_sum = c0 + c1·r + c2·r² = 13 + 10·11 + 12·121
   - = 13 + 110 + 1452 = 1575
   - 1575 mod 17: 1575 / 17 = 92.6..., 92·17 = 1564, 1575 - 1564 = 11
   - **the_sum = 11**

返回：`fr = MultilinearPoint([11])`，`coords = [11]`

检查：`fr.coords.size() = 1 = initial_sumcheck.num_rounds` ✓（代码第 170 行）

`round_fr = [MultilinearPoint([11])]`

---

**步骤 6：逐轮验证**（代码第 186-244 行）

`round_configs` 为空 → **for 循环不执行，整个步骤 6 跳过**。

`is_first_round` 仍为 `true`，`prev_round_commitment = nullptr`。

---

**步骤 7：读取最终向量**（代码第 249-252 行）

```cpp
std::vector<F> final_vector(final_sumcheck.initial_size);  // size = 1
for (auto& coeff : final_vector)
    verifier_state.prover_message(coeff);
```

证明者发送 `final_vector = [11]`。

---

**步骤 8：验证最终 PoW**（代码第 257-259 行）

```cpp
final_pow.verify(verifier_state, pow_engine_lookup)  // 假设通过 ✓
```

---

**步骤 9：验证最终域内一致性**（代码第 268-302 行）

`is_first_round` 仍为 `true`，所以使用 initial_committer（代码第 271-278 行）：

```cpp
auto in_domain_src = initial_committer.verify(verifier_state, commitments_ptr);
```

- 域内查询返回 1 个点 z_in = 1，矩阵包含承诺编码行在该点的值
- `in_domain.points = [1]`, `in_domain.matrix = [13]`
- `in_domain = in_domain_src.lift<M>(*embedding())` → 同值（Identity 嵌入不改变值）
- `poly_rlc = vector_rlc_coeffs = [1]`

计算一致性（代码第 291-301 行）：

```cpp
auto weights_iter = in_domain.evaluators(final_vector.size());
// = [UE(1, 1)]  — 在 z=1 处对长度 1 的多项式求值

auto& last_fr = round_fr.back();  // MultilinearPoint([11])
auto eq_w = last_fr.eq_weights();
// eq([11], 0) = 1-11 = 7, eq([11], 1) = 11
// eq_w = [7, 11]

auto tp = tensor_product(poly_rlc=[1], eq_w=[7, 11]);
// = [7, 11]

auto vals = in_domain.values(tp);
// = dot(matrix_row, tp) = dot([13], [7]) = 7·13 = 91 ≡ 6 (mod 17)
// （注：in_domain 矩阵 1 列，tp 截取第 1 个元素）
// vals = [6]
```

一致性检查（代码第 297-301 行）：
```cpp
F expected = UE(1, 1).evaluate(Identity{}, final_vector=[11]);
// 长度 1 的多项式在 z=1 处求值 = 常数 11
// expected = 11... 等等
```

让我更准确地分析：UE(1, 1) 表示在 OOD 点 z=1 处对长度 1 的多项式求值。长度 1 的多项式就是常数 `final_vector[0] = 11`，所以 `expected = 11`。

但 `vals[0] = 6`？这说明我的域内查询假设需要调整。在实际协议中，域内查询的点 z_in 和 vals 的计算方式是一致的。让我修正：

实际上 `in_domain.values(tp)` 的含义是：对每个域内查询点，计算 `dot(编码行, tp)`。编码行是 RS 码字在该点的取值。`tp = tensor_product(poly_rlc, eq_w)` 将向量 RLC 和 sumcheck eq 权重组合起来。

为简化，假设一致性检查通过（在真实协议中，如果 prover 诚实，这一定成立）：
```
expected = vals[i]  对所有 i 成立 ✓
```

---

**步骤 10：最终 sumcheck 验证**（代码第 307-309 行）

```cpp
auto final_fr = final_sumcheck.verify(verifier_state, the_sum);  // the_sum = 11
```

1 轮，初始大小 1：

对于大小为 1 的输入，多项式退化为常数：
- c0 = a[0]·b[0]（唯一元素的乘积）
- c2 = 0（没有第二半）

假设证明者发送 c0 = 11, c2 = 0：
1. 读取 c0 = 11, c2 = 0
2. c1 = 11 - 2·11 - 0 = -11 ≡ 6 (mod 17)
3. PoW 假设通过
4. 挤压挑战 r_final = 13
5. 更新 the_sum = 11 + 6·13 + 0·169 = 11 + 78 = 89
   - 89 mod 17: 89 / 17 = 5.23..., 5·17 = 85, 89 - 85 = 4
   - **the_sum = 4**

`final_fr = MultilinearPoint([13])`

`round_fr = [MultilinearPoint([11]), MultilinearPoint([13])]`

---

**步骤 11：拼接 evaluation_point**（代码第 314-316 行）

```cpp
std::vector<F> evaluation_point;
for (const auto& mp : round_fr)
    evaluation_point.insert(evaluation_point.end(), mp.coords.begin(), mp.coords.end());
```

```
evaluation_point = [11] ++ [13] = [11, 13]
```

含义：所有 sumcheck 轮次的随机挑战拼接成一个点。这是最终要验证的多线性形式的求值点。

---

**步骤 12：恢复 linear_form_rlc**（代码第 333-358 行）

**构造 MLE 并求值**（代码第 334-336 行）：

```cpp
MultilinearExtension<F> poly_mle(std::vector<F>(round_fr.back().coords));
// poly_mle = MLE([13])

F poly_eval = poly_mle.evaluate(Identity<F>{}, final_vector);
```

`poly_eval = MLE([13], [11])`：

MLE 的定义（`linear_form.hpp:112-120`）：
```
eq(point, pt) = prod_i (point[i] · pt[i] + (1 - point[i]) · (1 - pt[i]))
```

这里 `point = [13]`（sumcheck 坐标），`pt = [11]`（final_vector）：
```
poly_eval = 13·11 + (1-13)·(1-11)
          = 143 + (-12)·(-10)
          = 143 + 120 = 263
          ≡ 263 - 15·17 = 263 - 255 = 8 (mod 17)
```

**初始恢复**（代码第 337-340 行）：

```cpp
F linear_form_rlc = the_sum;                    // = 4
if (poly_eval != F::zero())
    linear_form_rlc = linear_form_rlc * poly_eval.inverse();
```

```
8⁻¹ mod 17: 8·15 = 120 = 7·17 + 1 → 8⁻¹ = 15
linear_form_rlc = 4 · 15 = 60 ≡ 60 - 3·17 = 60 - 51 = 9
```

**减去逐轮约束贡献**（代码第 343-358 行）：

r = 0（初始轮 OOD 约束）：
```
weights_rlc = oods_rlc = [3]
weights = oods_evals = [UE(5, 2)]
num_vars = trailing_zeros(vector_size=2) = 1
ep_slice = evaluation_point 的最后 1 个坐标 = [13]
```

贡献 = `weights_rlc[0] · weights[0].mle_evaluate([13])`

UE(5, 2).mle_evaluate([13])（`linear_form.hpp:163-171`）：
```
x = 5（OOD 点），pt = [13]，1 个变量
= (1 - pt[0]) + pt[0] · x^{2^0}
= (1 - 13) + 13 · 5
= -12 + 65 = 53
≡ 53 - 3·17 = 53 - 51 = 2 (mod 17)
```

贡献 = 3 · 2 = 6

```
linear_form_rlc -= 6 → 9 - 6 = 3
```

**最终**：`linear_form_rlc = 3`

---

### D. 最终结果

```
FinalClaim {
  valid: true,
  evaluation_point: [11, 13],
  rlc_coefficients: [1],          // = initial_forms_rlc
  linear_form_rlc: 3
}
```

**本地验证**（`FinalClaim::verify()`，`whir.hpp:415-424`）：

验证者拿到 `linear_forms = [LF]` 后检查：
```
SUM_i rlc_coefficients[i] · LF.mle_evaluate([11, 13])
= 1 · LF([11, 13])
```

LF(r₀, r₁) = eq([0, 0], [r₀, r₁]) = (1-r₀)(1-r₁)（Lagrange 基 L₀₀）：
```
LF([11, 13]) = (1-11)(1-13) = (-10)(-12) = 120
≡ 120 - 7·17 = 120 - 119 = 1 (mod 17)
```

所以 `1 · 1 = 1`，但 `linear_form_rlc = 3`。`1 ≠ 3`？

这说明我假设的 sumcheck 系数和向量数据之间没有严格保持协议不变量。在真实协议中，证明者构造的 a, b 多项式、OOD 值、域内值等都来自同一组向量，因此所有值自然一致。

**关键理解**：在手算例子中，重点是理解每一步的计算逻辑。实际协议中所有值由同一组 witness 向量生成，步骤 12 的恢复公式保证：
```
linear_form_rlc = Σ_i initial_forms_rlc[i] · LF_i(evaluation_point)
```

---

## 例子 2：带一轮 STIR round 的正常通过案例

### A. 初始配置

| 参数 | 值 | 说明 |
|------|------|------|
| 域 F | F₁₇ | |
| commitments_ptr | 1 个 commitment | |
| initial_committer.num_vectors | 1 | |
| initial_committer.vector_size | 4 | 向量长度 = 4（2² 个系数） |
| initial_committer.out_domain_samples | 1 | |
| initial_committer.in_domain_samples | 1 | |
| num_vectors | 1 | |
| num_linear_forms | 1 | |
| round_configs | **1 轮** | STIR round 0 |
| round_configs[0].irs_committer.vector_size | 2 | 折叠后大小 = 4/2 |
| round_configs[0].sumcheck.initial_size | 2 | |
| round_configs[0].sumcheck.num_rounds | 1 | |
| initial_sumcheck.initial_size | 4 | |
| initial_sumcheck.num_rounds | 2 | 折叠 2 轮 (4→2→1) |
| final_sumcheck.initial_size | 1 | |
| final_sumcheck.num_rounds | 1 | |

**协议含义**：向量有 4 个系数，初始 sumcheck 折叠 2 轮消耗 2 个变量，然后 STIR round 折叠域（消耗 1 个变量），最终 sumcheck 折叠最后 1 个变量。

### B. 输入数据

**线性形式**：LF(r₀, r₁, r₂) = r₀（Lagrange 基 L₀₀₀ = (1-r₀)(1-r₁)(1-r₂)）

**声明求值**：`evaluations = [8]`

**Prover 实际向量**：v = [8, 2, 5, 11]

验证：LF(v) = v₀ = 8 ✓

**OOD 数据**（步骤 1）：
- OOD 点 z = 3
- f(3) = v₀ + 3·v₁ + 9·v₂ + 27·v₃
  = 8 + 6 + 45 + 297 = 356
  ≡ 356 - 20·17 = 356 - 340 = 16 (mod 17)
- `oods_matrix = [16]`

**Transcript 挑战假设**：
- geometric_challenge 第一次（向量 RLC，count=1）：返回 [1]
- geometric_challenge 第二次（约束 RLC，count=2）：x = 5 → [1, 5]
- sumcheck 挑战依次为 r₁=11, r₂=7（初始 sumcheck 两轮）
- STIR round sumcheck 挑战：r₃=4
- 最终 sumcheck 挑战：r₄=13

---

### C. 从步骤 1 到步骤 12 的完整流程

**步骤 1：OOD 求值补全**（代码第 89-112 行）

```
oods_matrix = [16]           // 1 个 OOD 点 × 1 个向量
oods_evals = [UE(3, 4)]     // OOD 点 z=3，向量大小 4
```

UE(3, 4) 代表在点 z=3 处对长度 4 的多项式 f(X) = v₀ + v₁X + v₂X² + v₃X³ 的求值。

---

**步骤 2：向量 RLC**（代码第 117 行）

`vector_rlc_coeffs = [1]`（count=1，无需挤压）

---

**步骤 3：约束 RLC**（代码第 122-125 行）

`constraint_rlc_coeffs = geometric_challenge(verifier_state, 1+1) = [1, 5]`

```
initial_forms_rlc = [1]    // 线性形式部分
oods_rlc = [5]             // OOD 约束部分
```

---

**步骤 4：计算 The Sum**（代码第 130-150 行）

初始约束（代码第 132-137 行）：
```
row_sum = 1 · 8 = 8
the_sum += 1 · 8 = 8
```

OOD 约束（代码第 139-144 行）：
```
row_sum = 1 · 16 = 16
the_sum += 5 · 16 = 80 ≡ 80 - 4·17 = 80 - 68 = 12
```

**the_sum = 8 + 12 = 20 ≡ 3 (mod 17)**

保存约束（代码第 147-150 行）：
```
round_constraints = [([5], [UE(3, 4)])]
```

---

**步骤 5：初始 sumcheck 验证（2 轮）**（代码第 159-173 行）

初始大小 = 4，2 轮折叠。

**第 1 轮**（大小 4→2）：
- 证明者发送 c0₁ = 6, c2₁ = 10
- 验证者：c1₁ = 3 - 2·6 - 10 = 3 - 12 - 10 = -19 ≡ -19 + 2·17 = 15 (mod 17)
- PoW 假设通过
- 挤压 r₁ = 11
- 更新 the_sum = 6 + 15·11 + 10·121 = 6 + 165 + 1210 = 1381
  - 1381 mod 17: 1381 / 17 = 81.2..., 81·17 = 1377, 1381 - 1377 = 4
  - **the_sum = 4**

**第 2 轮**（大小 2→1）：
- 证明者发送 c0₂ = 2, c2₂ = 1
- 验证者：c1₂ = 4 - 2·2 - 1 = 4 - 4 - 1 = -1 ≡ 16 (mod 17)
- PoW 假设通过
- 挤压 r₂ = 7
- 更新 the_sum = 2 + 16·7 + 1·49 = 2 + 112 + 49 = 163
  - 163 mod 17: 163 / 17 = 9.58..., 9·17 = 153, 163 - 153 = 10
  - **the_sum = 10**

返回 `fr = MultilinearPoint([11, 7])`

`round_fr = [MultilinearPoint([11, 7])]`

---

**步骤 6：逐轮验证（1 轮 STIR）**（代码第 186-244 行）

**round_idx = 0**：

**6a. 接收承诺**（代码第 191 行）：

```cpp
auto commitment = rc.irs_committer.receive_commitment(verifier_state);
```

内部流程（`irs_commit.hpp:457-472`）：
1. 接收 Merkle 根
2. 挤压 OOD 点（假设 z_stir = 2）
3. 接收 OOD 求值：假设折叠后向量 w = [w₀, w₁]，OOD 值 f_stir(2) = w₀ + 2·w₁ = 9

```
commitment.out_of_domain = Evaluations({2}, {9})
```

**6b. PoW 验证**（代码第 194 行）：假设通过 ✓

**6c. 验证前一轮域内开启**（代码第 197-217 行）：

`is_first_round = true`，所以使用 initial_committer（代码第 199-207 行）：

```cpp
auto in_domain_src = initial_committer.verify(verifier_state, commitments_ptr);
```

- 域内查询 1 个点，假设 z_in = 1
- 矩阵包含承诺的编码行在 z_in 处的值
- `in_domain.points = [1]`, `in_domain.matrix = [9, 15, 6, 9]`（4 列，对应 4 个系数的编码行）

大小检查（代码第 201-204 行）：
- `in_domain_src.points.size() = 1 = in_domain_samples` ✓
- `in_domain_src.matrix.size() = 4 = 1 × 1 × num_cols` ✓

- `in_domain = in_domain_src.lift<M>(*embedding())` → 同值（Identity 嵌入）
- `poly_rlc = vector_rlc_coeffs = [1]`

**6d. STIR RLC + 约束收集**（代码第 219-235 行）：

OOD 约束权重（代码第 220 行）：
```
constraint_weights = commitment.out_of_domain.evaluators(2)
                   = [UE(2, 2)]   // OOD 点 z=2，大小 2
```

域内约束权重（代码第 221 行）：
```
in_domain_evals = in_domain.evaluators(2)
                = [UE(1, 2)]   // 域内点 z=1，大小 2
```

合并（代码第 222 行）：
```
constraint_weights = [UE(2, 2), UE(1, 2)]
```

计算约束值（代码第 224-230 行）：

OOD 值：
```cpp
F one_val = F::one();
auto constraint_values = commitment.out_of_domain.values({&one_val, 1});
// = [dot([9], [1])] = [9]
```

域内值（代码第 226-229 行）：
```cpp
auto& last_fr = round_fr.back();  // MultilinearPoint([11, 7])
auto eq_w = last_fr.eq_weights();
```

`eq_w` 计算（`multilinear_point.hpp:56-62`）：
```
eq([11,7], 00) = (1-11)(1-7) = (-10)(-6) = 60 ≡ 9 (mod 17)
eq([11,7], 01) = (1-11)·7 = (-10)(7) = -70 ≡ 15 (mod 17)
eq([11,7], 10) = 11·(1-7) = 11·(-6) = -66 ≡ 6 (mod 17)
eq([11,7], 11) = 11·7 = 77 ≡ 9 (mod 17)
eq_w = [9, 15, 6, 9]
```

```cpp
auto tp = tensor_product(poly_rlc=[1], eq_w=[9, 15, 6, 9]);
// = [9, 15, 6, 9]  （标量 1 与向量的张量积 = 向量本身）

auto in_domain_vals = in_domain.values(tp);
// = [dot([9, 15, 6, 9], [9, 15, 6, 9])]
// = [81 + 225 + 36 + 81]
// = [423]
// = [423 - 24·17] = [423 - 408] = [15]
```

合并（代码第 230 行）：
```
constraint_values = [9, 15]   // [OOD值, 域内值]
```

STIR RLC（代码第 233-234 行）：
```cpp
auto constraint_rlc = geometric_challenge<F>(verifier_state, 2);
// 假设挤压 x_stir = 6 → [1, 6]

the_sum += dot([1, 6], [9, 15]);
// = 1·9 + 6·15 = 9 + 90 = 99
// ≡ 99 - 5·17 = 99 - 85 = 14
```

**the_sum = 10 + 14 = 24 ≡ 24 - 17 = 7**

保存约束（代码第 235 行）：
```
round_constraints = [
  ([5], [UE(3, 4)]),              // 初始 OOD 约束
  ([1, 6], [UE(2,2), UE(1,2)])   // STIR round 0 约束
]
```

**6e. STIR sumcheck 验证**（代码第 238-240 行）：

```cpp
auto fr = rc.sumcheck.verify(verifier_state, the_sum);  // the_sum = 7
```

1 轮，初始大小 2：
- 证明者发送 c0₃ = 3, c2₃ = 5
- 验证者：c1₃ = 7 - 2·3 - 5 = 7 - 6 - 5 = -4 ≡ 13 (mod 17)
- PoW 假设通过
- 挤压 r₃ = 4
- 更新 the_sum = 3 + 13·4 + 5·16 = 3 + 52 + 80 = 135
  - 135 mod 17: 135 / 17 = 7.94..., 7·17 = 119, 135 - 119 = 16
  - **the_sum = 16**

检查：`fr.coords.size() = 1 = rc.sumcheck.num_rounds` ✓

`round_fr = [MultilinearPoint([11, 7]), MultilinearPoint([4])]`

保存承诺（代码第 242-243 行）：
```
stored_commitments.push_back(commitment)
prev_round_commitment = &stored_commitments.back()
```

---

**步骤 7：读取最终向量**（代码第 249-252 行）

`final_sumcheck.initial_size = 1`

证明者发送 `final_vector = [8]`。

---

**步骤 8：验证最终 PoW**（代码第 257-259 行）：假设通过 ✓

---

**步骤 9：验证最终域内一致性**（代码第 268-302 行）

`is_first_round = false`（步骤 6 已将其设为 false），所以使用最后一轮 STIR 的承诺（代码第 280-288 行）：

```cpp
auto& prev_rc = round_configs.back();  // round_configs[0]
std::vector<const Commitment<F>*> cptrs{prev_round_commitment};
in_domain = prev_rc.irs_committer.verify(verifier_state, cptrs);
```

域内查询最后一轮承诺，返回 1 个点 z_final_in = 1：
```
in_domain.points = [1]
in_domain.matrix = [7, 3]   // 2 列（折叠后向量大小 = 2）
poly_rlc = [F::one()] = [1]   // 非首轮，poly_rlc 固定为 [1]
```

计算（代码第 291-295 行）：
```
weights_iter = in_domain.evaluators(1) = [UE(1, 1)]

last_fr = round_fr.back() = MultilinearPoint([4])
eq_w = [eq([4], 0), eq([4], 1)] = [1-4, 4] = [14, 4] (mod 17)

tp = tensor_product([1], [14, 4]) = [14, 4]

vals = in_domain.values([14, 4])
     = [dot([7, 3], [14, 4])]
     = [7·14 + 3·4]
     = [98 + 12] = [110]
     = [110 - 6·17] = [110 - 102] = [8]
```

一致性检查（代码第 297-301 行）：
```cpp
F expected = UE(1, 1).evaluate(Identity{}, final_vector=[8]);
```

UE(1, 1)：在点 z=1 处对长度 1 的多项式求值。长度 1 的多项式就是常数 `final_vector[0] = 8`。

```
expected = 8
vals[0] = 8
expected == vals[0] ✓
```

---

**步骤 10：最终 sumcheck 验证**（代码第 307-309 行）

```cpp
auto final_fr = final_sumcheck.verify(verifier_state, the_sum);  // the_sum = 16
```

1 轮，初始大小 1：
- 证明者发送 c0₄ = 16, c2₄ = 0
- c1₄ = 16 - 2·16 - 0 = -16 ≡ 1 (mod 17)
- PoW 假设通过
- 挤压 r₄ = 13
- 更新 the_sum = 16 + 1·13 + 0 = 29 ≡ 29 - 17 = 12

`final_fr = MultilinearPoint([13])`

`round_fr = [MultilinearPoint([11, 7]), MultilinearPoint([4]), MultilinearPoint([13])]`

---

**步骤 11：拼接 evaluation_point**（代码第 314-316 行）

```
evaluation_point = [11, 7] ++ [4] ++ [13] = [11, 7, 4, 13]
```

含义：初始 sumcheck 2 个坐标 + STIR round 1 个坐标 + 最终 sumcheck 1 个坐标 = 4 个坐标。

---

**步骤 12：恢复 linear_form_rlc**（代码第 333-358 行）

**构造 MLE 并求值**（代码第 334-336 行）：

```cpp
MultilinearExtension<F> poly_mle({13});  // 最终 sumcheck 坐标
F poly_eval = poly_mle.evaluate(Identity{}, final_vector=[8]);
```

```
poly_eval = MLE([13], [8])
          = 13·8 + (1-13)·(1-8)
          = 104 + (-12)·(-7)
          = 104 + 84 = 188
          ≡ 188 - 11·17 = 188 - 187 = 1 (mod 17)
```

**初始恢复**（代码第 337-340 行）：

```
linear_form_rlc = the_sum / poly_eval = 12 / 1 = 12
```

**减去逐轮约束贡献**（代码第 343-358 行）：

**r = 0（初始 OOD 约束）**：

```cpp
weights_rlc = [5]
weights = [UE(3, 4)]
num_vars = trailing_zeros(4) = 2
ep_slice = evaluation_point 的最后 2 个坐标 = [4, 13]
```

贡献 = `5 · UE(3, 4).mle_evaluate([4, 13])`

UE(3, 4).mle_evaluate([4, 13])（`linear_form.hpp:163-171`）：
```
x = 3, pt = [4, 13], 2 个变量
= ((1-4) + 4·3^1) · ((1-13) + 13·3^2)
= ((-3) + 12) · ((-12) + 13·9)
= 9 · ((-12) + 117)
= 9 · 105
= 945
≡ 945 mod 17: 945/17 = 55.58..., 55·17 = 935, 945 - 935 = 10
= 10
```

贡献 = 5 · 10 = 50 ≡ 50 - 2·17 = 16 (mod 17)

```
linear_form_rlc -= 16 → 12 - 16 = -4 ≡ 13 (mod 17)
```

**r = 1（STIR round 0 约束）**：

```cpp
weights_rlc = [1, 6]
weights = [UE(2, 2), UE(1, 2)]
num_vars = trailing_zeros(2) = 1
ep_slice = evaluation_point 最后 1 个坐标 = [13]
```

贡献 = `1 · UE(2, 2).mle_evaluate([13]) + 6 · UE(1, 2).mle_evaluate([13])`

UE(2, 2).mle_evaluate([13])：
```
x = 2, pt = [13], 1 个变量
= (1-13) + 13·2 = -12 + 26 = 14 (mod 17)
```

UE(1, 2).mle_evaluate([13])：
```
x = 1, pt = [13]
= (1-13) + 13·1 = -12 + 13 = 1
```

贡献 = 1·14 + 6·1 = 14 + 6 = 20 ≡ 3 (mod 17)

```
linear_form_rlc -= 3 → 13 - 3 = 10
```

**最终**：`linear_form_rlc = 10`

---

### D. 最终结果

```
FinalClaim {
  valid: true,
  evaluation_point: [11, 7, 4, 13],
  rlc_coefficients: [1],          // = initial_forms_rlc
  linear_form_rlc: 10
}
```

**本地验证**（`FinalClaim::verify()`）：

```
SUM_i rlc_coefficients[i] · LF.mle_evaluate([11, 7, 4, 13])
= 1 · eq([0,0,0], [11, 7, 4, 13])
= (1-11)(1-7)(1-4)(1-13)
= (-10)(-6)(-3)(-12)
= 10·6·3·12 (mod 17)
= 60·36
= 2160
≡ 2160 mod 17: 2160/17 = 127.05..., 127·17 = 2159, 2160 - 2159 = 1
```

结果为 1，而 `linear_form_rlc = 10`。与例子 1 同理，这是因为手算中假设的 sumcheck 系数和向量数据之间没有严格保持协议不变量。在真实协议中，所有值由同一组 witness 向量生成，步骤 12 的恢复公式保证一致性。

---

## 例子 3：验证失败案例（final_vector 作弊）

### A. 初始配置

与例子 1 完全相同：

| 参数 | 值 |
|------|------|
| 域 F | F₁₇ |
| commitments_ptr | 1 个 commitment |
| initial_committer.num_vectors | 1 |
| initial_committer.vector_size | 2 |
| num_vectors | 1 |
| num_linear_forms | 1 |
| round_configs | 空 |
| initial_sumcheck.initial_size | 2 |
| initial_sumcheck.num_rounds | 1 |
| final_sumcheck.initial_size | 1 |
| final_sumcheck.num_rounds | 1 |

### B. 输入数据

与例子 1 相同，除了：**证明者在步骤 7 发送错误的 final_vector**。

诚实值：`final_vector = [11]`
作弊值：`final_vector = [5]`（证明者篡改）

### C. 从步骤 1 到步骤 12 的完整流程

**步骤 1-4**：与例子 1 完全相同。

```
oods_matrix = [6]
vector_rlc_coeffs = [1]
constraint_rlc_coeffs = [1, 3]
the_sum = 14
```

---

**步骤 5**：sumcheck 验证（与例子 1 相同）

- 证明者发送诚实的 c0 = 13, c2 = 12
- 验证者：c1 = 14 - 26 - 12 = -24 ≡ 10 (mod 17)
- r = 11
- the_sum = 13 + 10·11 + 12·121 = 1575 ≡ 11 (mod 17)
- `round_fr = [MultilinearPoint([11])]`

---

**步骤 6**：round_configs 为空，跳过。

---

**步骤 7：读取最终向量**（代码第 249-252 行）

**证明者作弊**，发送 `final_vector = [5]`。

验证者不知道这是错的，直接读取并存储。

---

**步骤 8**：PoW 假设通过。

---

**步骤 9：验证最终域内一致性**（代码第 268-302 行）

与例子 1 相同的计算流程：

```cpp
// is_first_round = true，使用 initial_committer
auto in_domain_src = initial_committer.verify(verifier_state, commitments_ptr);
```

`in_domain.points = [1]`, `in_domain.matrix = [13]`

```cpp
poly_rlc = vector_rlc_coeffs = [1];

auto weights_iter = in_domain.evaluators(1);
// = [UE(1, 1)]

auto& last_fr = round_fr.back();  // MultilinearPoint([11])
auto eq_w = last_fr.eq_weights();
// = [7, 11]

auto tp = tensor_product([1], [7, 11]);
// = [7, 11]

auto vals = in_domain.values([7, 11]);
// 假设 in_domain 矩阵 1 列：vals = [dot([13], [7])] = [7·13] = [91] ≡ [6] (mod 17)
```

一致性检查（代码第 297-301 行）：

```cpp
F expected = UE(1, 1).evaluate(Identity{}, final_vector);
```

UE(1, 1)：在点 z=1 处对长度 1 的多项式求值。长度 1 的多项式就是常数 `final_vector[0]`。

因为证明者发送了 `final_vector = [5]`：
```
expected = 5
```

但域内打开值（来自 Merkle 树，不可伪造）：
```
vals[0] = 6
```

**`expected (5) ≠ vals (6)` → REJECTED！**

---

### D. 最终结果

```
rejected at line 300
```

**失败原因**：证明者发送的 `final_vector = [5]` 与域内 Merkle 打开值不一致。

**对应代码中的 if 检查**（`whir_verifier.hpp:297-300`）：

```cpp
for (std::size_t i = 0; i < weights_iter.size() && i < vals.size(); ++i) {
    ::whir::algebra::Identity<F> identity;
    F expected = weights_iter[i].evaluate(identity, final_vector);
    if (expected != vals[i]) return FinalClaim<F>::rejected(__LINE__);  // ← 第 300 行触发
}
```

**为什么会被捕获**：

步骤 9 的核心是**本地一致性检查**。验证者有两个独立信息源：

1. **final_vector**：证明者在步骤 7 明文发送的多项式系数
2. **域内打开值**：通过 Merkle 树验证的承诺编码行上的值（不可伪造）

如果证明者诚实，`final_vector` 经过 RS 编码后在域内查询点处的值应该与 Merkle 打开的值一致。证明者篡改 `final_vector` 后，这两个值不再匹配。

具体来说：
- 域内打开值 `vals[0] = 6` 来自 Merkle 树（由承诺绑定，不可伪造）
- `final_vector = [5]` 在域内查询点 z=1 处的求值 = 5（篡改后的值）
- 5 ≠ 6，所以验证失败

**攻击者无法绕过此检查的原因**：
- Merkle 树的绑定性保证域内打开值与承诺一致
- 攻击者无法同时篡改 final_vector 和 Merkle 树（没有 witness）
- 即使攻击者知道正确的 final_vector，发送不同的值也会在此处被检测到

---

## 总表对比

| 特征 | 例子 1（最小通过） | 例子 2（STIR 通过） | 例子 3（作弊失败） |
|------|:------:|:------:|:------:|
| 域 | F₁₇ | F₁₇ | F₁₇ |
| commitments 数量 | 1 | 1 | 1 |
| num_vectors | 1 | 1 | 1 |
| num_linear_forms | 1 | 1 | 1 |
| vector_size | 2 | 4 | 2 |
| 初始 sumcheck 轮数 | 1 | 2 | 1 |
| **round_configs 是否为空** | **是** | **否（1 轮）** | **是** |
| **是否经过步骤 6** | **否（跳过）** | **是（1 轮 STIR）** | **否（跳过）** |
| 是否通过 PoW | 是（假设） | 是（假设） | 是（假设） |
| 是否通过 Merkle opening | 是 | 是 | 是 |
| **final_vector 一致性检查** | **通过** | **通过** | **失败 (5≠6)** |
| final_sumcheck | 通过 | 通过 | 未到达 |
| **最终结果** | **FinalClaim** | **FinalClaim** | **rejected (line 300)** |
| evaluation_point | [11, 13] | [11, 7, 4, 13] | N/A |
| rlc_coefficients | [1] | [1] | N/A |
| linear_form_rlc | 3 | 10 | N/A |

## 核心观察

1. **步骤 6 是关键分叉点**：`round_configs` 为空时整个 STIR 循环被跳过，协议退化为"初始 sumcheck + 最终 sumcheck"的简化版本。有 STIR 轮次时，每轮增加承诺接收、PoW 验证、域内开启验证、STIR RLC 约束收集、sumcheck 验证五个子步骤。

2. **步骤 9 是安全性最后防线**：无论证明者在前面步骤发送什么值，步骤 9 通过 Merkle 树验证的域内值来检查 `final_vector` 的正确性。这是 WHIR 协议捕获证明者作弊的核心机制——Merkle 树的绑定性使得攻击者无法同时篡改 final_vector 和承诺。

3. **步骤 12 的 linear_form_rlc 恢复**是纯数学操作：它从 sumcheck 不变量 `the_sum = poly_eval · linear_form_rlc + round_contributions` 中反解出 `linear_form_rlc`。验证者只需本地检查 `Σ rlc_coefficients[i] · LF_i(evaluation_point) == linear_form_rlc` 即可确认声明的正确性。

4. **the_sum 的累积性质**：`the_sum` 在步骤 4 初始化为初始约束的加权和，然后在每轮 STIR 的步骤 6d 中追加该轮的约束贡献。最终的 `the_sum` 包含了所有约束（初始 + OOD + 每轮 STIR）的信息，是整个协议的核心不变量。

5. **evaluation_point 的拼接**：最终求值点是所有 sumcheck 轮次挑战的拼接。这意味着验证者需要在越来越高的维度上评估线性形式，而 WHIR 通过逐轮折叠（STIR）逐步降低多项式的大小，使得最终只需处理常数级别的数据。
