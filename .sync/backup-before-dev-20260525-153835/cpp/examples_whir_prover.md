# WHIR `Config<M>::prove()` 完整运行例子

本文档基于 `whir_prover.hpp` 中 `Config<M>::prove()` 的 10 步证明流程，生成 3 个难度适中的完整运行例子。所有算术在简化有限域上手算演示。

---

## 例子 1：单个 witness、多个向量、一个线性约束

### 初始设置

使用简化有限域 **GF(17)**（模 17 的整数）。

**协议参数：**

- `initial_size = 4`（2 个变量，即 `num_vars = 2`）
- `num_vectors = 2`（2 个输入向量）
- `num_linear_forms = 1`（1 个约束线性形式）
- 1 个 witness 管理全部 2 个向量
- `round_configs` 为空（无 STIR 轮次）
- 初始 sumcheck：`initial_size = 4, num_rounds = 2`
- 最终 sumcheck：`initial_size = 1, num_rounds = 0`

**数据结构说明：**

- `Transcript`：Fiat-Shamir 转录本，证明者和验证者共享的伪随机源。证明者往里写消息，验证者从中挤压随机挑战。
- `irs_commit::Witness<Source, Target>`：IRS 承诺产生的见证，包含 RS 编码矩阵、Merkle 树路径、OOD（Out-of-Domain）求值。
- `LinearForm<Target>`：线性形式抽象基类。本例使用 `Covector<F>`（具体向量的内积）。

### 输入数据

```
vector[0] = [1, 2, 3, 4]    （基域 GF(17)）
vector[1] = [5, 6, 7, 8]    （基域 GF(17)）

linear_form[0] = Covector([1, 1, 1, 1])   // 求和约束

evaluations[0] = linear_form[0](vector[0]) = 1+2+3+4 = 10 (mod 17)
evaluations[1] = linear_form[0](vector[1]) = 5+6+7+8 = 26 mod 17 = 9
```

**witness 构造（commit 阶段产生）：**

- 1 个 witness，管理 2 个向量
- `witness.out_of_domain.points = [3]`（1 个 OOD 点 z=3）
- OOD 求值：对向量 v，OOD 求值为 `P(z) = sum_i v[i] * z^i`
  - `v0_at_3 = 1*1 + 2*3 + 3*9 + 4*27 = 1+6+27+108 = 142 mod 17 = 6`
  - `v1_at_3 = 5*1 + 6*3 + 7*9 + 8*27 = 5+18+63+216 = 302 mod 17 = 13`
- `witness.out_of_domain.matrix = [6, 13]`（1 行 × 2 列）

---

### 步骤 1：补全跨承诺 OOD 求值

**目的：** STIR 折叠要求每个向量在每个 OOD 点都有求值。由于只有 1 个 witness 管理全部 2 个向量，无需跨承诺补全。

**执行过程：**

```
vector_offset = 0
遍历 witness（只有 1 个）:
  w_evals = witness.out_of_domain.evaluators(4) = [UnivariateEvaluation(3, 4)]
  w_cols = 2

  对于 ei=0（OOD 点 z=3）:
    对于 j=0: j >= 0 && j < 2 → 属于当前 witness
      oods_matrix.push_back(matrix[0*2 + 0]) = 6
    对于 j=1: j >= 0 && j < 2 → 属于当前 witness
      oods_matrix.push_back(matrix[0*2 + 1]) = 13
    oods_evals.push_back(UnivariateEvaluation(3, 4))
```

**输出：**

- `oods_evals = [UnivariateEvaluation(3, 4)]` — 1 个 OOD 求值器
- `oods_matrix = [6, 13]` — 1×2 矩阵（1 个 OOD 点，2 个向量）

**关键理解：** 如果有 2 个 witness 各管理 1 个向量，那么每个 witness 只预计算了自己向量的 OOD 求值。另一个向量的 OOD 求值需要通过 `oods_eval.evaluate(*embedding(), vectors_span[j])` 现场计算并通过 `prover_state.prover_message(eval)` 发送给验证者。

---

### 步骤 2：向量 RLC（随机线性组合）

**目的：** 将多个向量通过几何级数挑战组合为一个向量，减少后续处理的向量数。

**执行过程：**

```
vector_rlc_coeffs = geometric_challenge<F>(prover_state, 2)
  → 从 transcript 挤压一个随机元素 α
  → 返回 [1, α, α², ...] 的前 2 项
  → 假设 α = 5（由 Fiat-Shamir transcript 决定）
  → vector_rlc_coeffs = [1, 5]
```

**构造组合向量 `vector`：**

```
vector = lift(vector[0])                        // 基域→扩域映射（本例为恒等映射）
       = [1, 2, 3, 4]

然后对 i=1:
  mixed_scalar_mul_add(vector, vector_rlc_coeffs[1], vector[1])
  → vector[i] += 5 * vector[1][i]
  → vector = [1+5*5, 2+5*6, 3+5*7, 4+5*8]
           = [1+25, 2+30, 3+35, 4+40]
           = [26, 32, 38, 44]
           = [9, 15, 4, 10]   (mod 17)
```

**输出：**

- `vector_rlc_coeffs = [1, 5]`
- `vector = [9, 15, 4, 10]`（扩域上的组合向量）

**关键理解：** `geometric_challenge` 生成几何级数 `[1, α, α², ...]`，这样验证者只需挤压一个随机元素 α，就能得到 n 个独立的 RLC 系数（在有限域上以高概率线性无关）。`vector[0]` 乘以 1（不变），`vector[1]` 乘以 α=5。

---

### 步骤 3：约束 RLC

**目的：** 将所有约束（线性形式 + OOD 约束）通过 RLC 合并为一个协向量（covector）。

**执行过程：**

```
constraint_rlc_coeffs = geometric_challenge<F>(prover_state, 1 + 1)
  // 1 个 linear_form + 1 个 OOD 求值器 = 2 个约束
  → 从 transcript 挤压随机元素 β
  → 假设 β = 7
  → constraint_rlc_coeffs = [1, 7]

initial_forms_rlc = constraint_rlc_coeffs[0..1) = [1]   // 初始约束系数
oods_rlc = constraint_rlc_coeffs[1..2) = [7]             // OOD 约束系数
```

**构造协向量 `covector`：**

```
covector = [0, 0, 0, 0]    （长度 = initial_size = 4）

// 累积初始线性形式
linear_forms[0]->accumulate(covector, F::one())
  → Covector([1,1,1,1]).accumulate(covector, 1)
  → covector[i] += 1 * [1,1,1,1][i]
  → covector = [1, 1, 1, 1]

// 由于只有 1 个 linear_form，循环 i=1..0 不执行

// 累积 OOD 求值器（在步骤 4 中也会做，这里先记下）
```

**输出：**

- `constraint_rlc_coeffs = [1, 7]`
- `initial_forms_rlc = [1]`
- `oods_rlc = [7]`
- `covector = [1, 1, 1, 1]`（在步骤 4 中会继续累积 OOD 部分）

**关键理解：** `covector` 是所有线性形式的加权和。`linear_forms[0]->accumulate(covector, 1)` 的含义是：将 `linear_form[0]` 的系数乘以权重 1 后累加到 `covector` 上。对于 `Covector` 类型，`accumulate(acc, s)` 就是 `acc += s * vec`。

---

### 步骤 4：计算 `the_sum`

**目的：** 计算初始 sumcheck 的目标值，即所有约束的双重 RLC 和。

**公式：**

```
the_sum = Σ_i constraint_rlc[i] * (Σ_j vector_rlc[j] * eval[i][j])
        + Σ_i oods_rlc[i]       * (Σ_j vector_rlc[j] * oods_matrix[i][j])
```

**执行过程：**

```
the_sum = 0

// 初始约束部分
i=0: row_sum = vector_rlc[0]*eval[0] + vector_rlc[1]*eval[1]
              = 1*10 + 5*9 = 10 + 45 = 55 mod 17 = 4
     the_sum += constraint_rlc[0] * row_sum = 1 * 4 = 4

// OOD 约束部分：先累积 OOD 求值器到 covector
UnivariateEvaluation(3,4).accumulate_many(oods_evals, covector, oods_rlc)
  → oods_evals = [UE(3,4)], oods_rlc = [7]
  → covector[i] += 7 * 3^i
  → covector[0] += 7*1  = 7  → [8, 1, 1, 1]
  → covector[1] += 7*3  = 21 mod 17 = 4 → [8, 5, 1, 1]
  → covector[2] += 7*9  = 63 mod 17 = 12 → [8, 5, 13, 1]
  → covector[3] += 7*27 = 189 mod 17 = 2 → [8, 5, 13, 3]

i=0 (OOD): row_sum = vector_rlc[0]*oods_matrix[0] + vector_rlc[1]*oods_matrix[1]
                    = 1*6 + 5*13 = 6 + 65 = 71 mod 17 = 3
            the_sum += oods_rlc[0] * row_sum = 7 * 3 = 21 mod 17 = 4

the_sum = 4 + 4 = 8
```

**输出：**

- `covector = [8, 5, 13, 3]`
- `the_sum = 8`

**关键理解：**

- `the_sum` 是初始 sumcheck 要验证的目标值：`<vector, covector> = the_sum`
- 验证：`<[9,15,4,10], [8,5,13,3]> = 9*8 + 15*5 + 4*13 + 10*3 = 72+75+52+30 = 229 mod 17 = 8` ✓
- `covector` 是所有约束（初始线性形式 + OOD 求值器）的加权和，权重来自 `constraint_rlc_coeffs`

---

### 步骤 5：初始 sumcheck

**目的：** 运行 sumcheck 协议验证 `<vector, covector> = the_sum`，每轮获得一个折叠坐标。

**配置：** `initial_sumcheck.initial_size = 4, num_rounds = 2`

**Sumcheck 第 1 轮：**

```
a = vector = [9, 15, 4, 10]
b = covector = [8, 5, 13, 3]
sum = 8, half = 2

a0 = [9, 15], a1 = [4, 10]
b0 = [8, 5], b1 = [13, 3]

c0 = Σ a0[i]*b0[i] = 9*8 + 15*5 = 72+75 = 147 mod 17 = 11
c2 = Σ (a1[i]-a0[i])*(b1[i]-b0[i]) = (4-9)*(13-8) + (10-15)*(3-5)
   = (-5)*5 + (-5)*(-2) = -25+10 = -15 mod 17 = 2
c1 = sum - 2*c0 - c2 = 8 - 22 - 2 = -16 mod 17 = 1

// 发送 c0=11, c2=2 给验证者
prover_state.prover_message(11)
prover_state.prover_message(2)

// 挤压折叠随机性 r1
r1 = prover_state.verifier_message<F>()  // 假设 r1 = 4

// 折叠：v'[i] = v[i] + r * (v[half+i] - v[i])
fold(a, 4): a = [9+4*(4-9), 15+4*(10-15)] = [9-20, 15-20] = [-11, -5] = [6, 12] (mod 17)
fold(b, 4): b = [8+4*(13-8), 5+4*(3-5)] = [8+20, 5-8] = [28, -3] = [11, 14] (mod 17)

// 更新 sum
sum = (c2*r1 + c1)*r1 + c0 = (2*4+1)*4+11 = 9*4+11 = 47 mod 17 = 13

// 验证：<[6,12], [11,14]> = 66+168 = 234 mod 17 = 13 ✓
```

**Sumcheck 第 2 轮：**

```
a = [6, 12], b = [11, 14], sum = 13, half = 1

c0 = 6*11 = 66 mod 17 = 15
c2 = (12-6)*(14-11) = 6*3 = 18 mod 17 = 1
c1 = 13 - 2*15 - 1 = -18 mod 17 = 16

// 发送 c0=15, c2=1
prover_state.prover_message(15)
prover_state.prover_message(1)

// 挤压 r2，假设 r2 = 7
r2 = 7

// 折叠
fold(a, 7): a = [6+7*(12-6)] = [6+42] = [48] = [14] (mod 17)
fold(b, 7): b = [11+7*(14-11)] = [11+21] = [32] = [15] (mod 17)

// 更新 sum
sum = (1*7+16)*7+15 = 23*7+15 = 176 mod 17 = 6

// 验证：<[14], [15]> = 210 mod 17 = 6 ✓
```

**输出：**

- `evaluation_point = [4, 7]`（两轮折叠随机性）
- `vector = [14]`（折叠至长度 1）
- `covector = [15]`（折叠至长度 1）
- `the_sum = 6`
- `last_fr_coords = [4, 7]`

---

### 步骤 6：逐轮 STIR

`round_configs` 为空，跳过。

---

### 步骤 7：发送最终向量

```
vector = [14]，长度 = final_sumcheck.initial_size = 1 ✓
prover_state.prover_message(14)   // 发送最终系数
```

---

### 步骤 8：最终 PoW

```
final_pow.prove(prover_state, pow_engine_lookup)
// 执行工作量证明（mock：无操作）
```

---

### 步骤 9：开启最终 witness

```
is_first_round == true（从未进入 STIR 循环）
→ 打开 initial_committer 的 witness
→ 发送 Merkle 路径和域内求值
```

---

### 步骤 10：最终 sumcheck

```
final_sumcheck: initial_size = 1, num_rounds = 0
→ 无轮次可执行
→ final_fr.coords = []（空）
→ evaluation_point 不变
```

---

### 最终返回值

```cpp
FinalClaim<F>{
    valid = true,
    evaluation_point = [4, 7],           // 2 个 sumcheck 坐标
    rlc_coefficients = [1],              // initial_forms_rlc（1 个线性形式的 RLC 系数）
    linear_form_rlc = 0                  // F::zero()，由验证者计算
}
```

验证者检查：`SUM_i rlc_coefficients[i] * linear_forms[i].mle_evaluate([4,7]) == 0`
即 `1 * Covector([1,1,1,1]).mle_evaluate([4,7])` 应等于 `linear_form_rlc`。

---

### 这个例子对应代码中的变量

| 变量 | 值 | 说明 |
|------|-----|------|
| `num_vectors` | 2 | 输入向量数 |
| `num_linear_forms` | 1 | 线性约束数 |
| `vector_rlc_coeffs` | [1, 5] | 向量 RLC 系数 |
| `constraint_rlc_coeffs` | [1, 7] | 约束 RLC 系数 |
| `oods_evals` | [UE(3,4)] | 1 个 OOD 求值器 |
| `oods_matrix` | [6, 13] | OOD 求值矩阵 |
| `vector` | [14] | 最终折叠向量 |
| `covector` | [15] | 最终折叠协向量 |
| `the_sum` | 6 | 最终 sumcheck 目标值 |
| `evaluation_point` | [4, 7] | 所有折叠坐标 |
| `last_fr_coords` | [4, 7] | 最后一轮折叠随机性 |
| `stored_round_witnesses` | {} | 无 STIR 轮 |
| `prev_round_witness` | nullptr | 无前一轮 |

---

## 例子 2：多个 witness、多个向量、多个线性约束（体现 OOD 补全）

### 初始设置

使用简化有限域 **GF(17)**。

**协议参数：**

- `initial_size = 4`（2 个变量）
- `num_vectors = 2`（2 个输入向量）
- `num_linear_forms = 2`（2 个约束线性形式）
- 2 个 witness，每个管理 1 个向量（`initial_committer.num_vectors = 1`）
- `round_configs` 为空（无 STIR 轮次）
- 初始 sumcheck：`initial_size = 4, num_rounds = 2`

**数据结构说明：**

- 2 个 witness 各自包含自己管理的 1 个向量的 OOD 求值
- 步骤 1 需要补全跨承诺的 OOD 求值

### 输入数据

```
vector[0] = [1, 2, 3, 4]     // witness[0] 管理
vector[1] = [5, 6, 7, 8]     // witness[1] 管理

linear_form[0] = Covector([1, 1, 1, 1])   // 求和
linear_form[1] = Covector([1, 0, 0, 0])   // 取首元素

eval[0*2+0] = lf[0](v[0]) = 1+2+3+4 = 10
eval[0*2+1] = lf[0](v[1]) = 5+6+7+8 = 26 mod 17 = 9
eval[1*2+0] = lf[1](v[0]) = 1
eval[1*2+1] = lf[1](v[1]) = 5
```

**witness 构造：**

```
witness[0]（管理 vector[0]）:
  OOD 点 z=3
  v0_at_3 = 1+2*3+3*9+4*27 = 142 mod 17 = 6
  → matrix = [6]，w_cols = 1

witness[1]（管理 vector[1]）:
  OOD 点 z=3
  v1_at_3 = 5+6*3+7*9+8*27 = 302 mod 17 = 13
  → matrix = [13]，w_cols = 1
```

---

### 步骤 1：补全跨承诺 OOD 求值

**这是本例的核心差异：** 每个 witness 只管理 1 个向量，但需要所有 2 个向量的 OOD 求值。

```
vector_offset = 0

--- witness[0] ---
w_evals = [UE(3,4)], w_cols = 1
ei=0 (z=3):
  j=0: 0 >= 0 && 0 < 1 → 属于 witness[0]
    oods_matrix.push_back(matrix[0]) = 6
  j=1: 1 >= 0 && 1 < 1 → 不属于！
    eval = UE(3,4).evaluate(vectors[1]) = 13
    prover_state.prover_message(13)       ← 发送给验证者
    oods_matrix.push_back(13)
  oods_evals.push_back(UE(3,4))
vector_offset = 1

--- witness[1] ---
w_evals = [UE(3,4)], w_cols = 1
ei=0 (z=3):
  j=0: 0 >= 1 && 0 < 2 → 不属于！
    eval = UE(3,4).evaluate(vectors[0]) = 6
    prover_state.prover_message(6)        ← 发送给验证者
    oods_matrix.push_back(6)
  j=1: 1 >= 1 && 1 < 2 → 属于 witness[1]
    oods_matrix.push_back(matrix[0]) = 13
  oods_evals.push_back(UE(3,4))
```

**输出：**

- `oods_evals = [UE(3,4), UE(3,4)]`（2 个求值器，同一点 z=3）
- `oods_matrix = [6, 13, 6, 13]`（2 行 × 2 列）
- 向 transcript 发送了 2 个跨承诺 OOD 求值（13 和 6）

**关键理解：** 两个 witness 共享同一个 OOD 点 z=3。witness[0] 不知道 vector[1] 在 z=3 处的求值，需要现场计算并发送。witness[1] 同理。验证者用相同逻辑重新计算并校验。

---

### 步骤 2：向量 RLC

```
vector_rlc_coeffs = geometric_challenge<F>(prover_state, 2)
  → 假设 α = 5 → [1, 5]

vector = lift([1,2,3,4]) = [1,2,3,4]
vector += 5 * [5,6,7,8] = [1+25, 2+30, 3+35, 4+40]
        = [26, 32, 38, 44] = [9, 15, 4, 10] (mod 17)
```

**输出：** `vector = [9, 15, 4, 10]`, `vector_rlc_coeffs = [1, 5]`

---

### 步骤 3：约束 RLC

```
约束总数 = 2 + 2 = 4
constraint_rlc_coeffs = geometric_challenge<F>(prover_state, 4)
  → 假设 β = 7 → [1, 7, 49 mod 17 = 15, 15*7 mod 17 = 3]
  → 即 [1, 7, 15, 3]

initial_forms_rlc = [1, 7]
oods_rlc = [15, 3]

covector = [0, 0, 0, 0]
lf[0] = Covector([1,1,1,1]).accumulate(covector, 1)
  → covector = [1, 1, 1, 1]
lf[1] = Covector([1,0,0,0]).accumulate(covector, 7)
  → covector = [1+7, 1, 1, 1] = [8, 1, 1, 1]
```

---

### 步骤 4：计算 `the_sum`

```
the_sum = 0

i=0: row_sum = 1*10 + 5*9 = 10+45 = 55 mod 17 = 4
     the_sum += 1 * 4 = 4

i=1: row_sum = 1*1 + 5*5 = 1+25 = 26 mod 17 = 9
     the_sum += 7 * 9 = 63 mod 17 = 12
     the_sum = 4 + 12 = 16

// OOD 求值器累积到 covector
accumulate_many([UE(3,4), UE(3,4)], covector, [15, 3])

UE(3,4) scalar=15: covector[i] += 15 * 3^i
  3^0=1, 3^1=3, 3^2=9, 3^3=27 mod 17=10
  covector = [8+15*1, 1+15*3, 1+15*9, 1+15*10]
           = [8+15, 1+45, 1+135, 1+150]
           = [23, 46, 136, 151]
           mod 17: [6, 12, 0, 15]

UE(3,4) scalar=3: covector[i] += 3 * 3^i
  covector = [6+3*1, 12+3*3, 0+3*9, 15+3*10]
           = [6+3, 12+9, 0+27, 15+30]
           = [9, 21, 27, 45]
           mod 17: [9, 4, 10, 11]

// OOD 约束求和
i=0: row_sum = 1*6 + 5*13 = 6+65 = 71 mod 17 = 3
     the_sum += 15 * 3 = 45 mod 17 = 11
     the_sum = 16 + 11 = 27 mod 17 = 10

i=1: row_sum = 1*6 + 5*13 = 3  （同上）
     the_sum += 3 * 3 = 9
     the_sum = 10 + 9 = 19 mod 17 = 2
```

**验证：** `<[9,15,4,10], [9,4,10,11]> = 9*9 + 15*4 + 4*10 + 10*11 = 81+60+40+110 = 291 mod 17 = 2` ✓

**输出：**

- `covector = [9, 4, 10, 11]`
- `the_sum = 2`

---

### 步骤 5：初始 sumcheck

`initial_sumcheck: initial_size=4, num_rounds=2`

**第 1 轮：**

```
a = [9, 15, 4, 10], b = [9, 4, 10, 11], sum = 2, half = 2

c0 = 9*9 + 15*4 = 81+60 = 141 mod 17 = 5
c2 = (4-9)*(10-9) + (10-15)*(11-4) = (-5)*1 + (-5)*7 = -5-35 = -40 mod 17 = 11
c1 = 2 - 2*5 - 11 = 2-10-11 = -19 mod 17 = 15

发送 c0=5, c2=11
假设 r1 = 4

fold(a,4): [9+4*(4-9), 15+4*(10-15)] = [9-20, 15-20] = [6, 12] (mod 17)
fold(b,4): [9+4*(10-9), 4+4*(11-4)] = [9+4, 4+28] = [13, 32] = [13, 15] (mod 17)

sum = (11*4+15)*4+5 = 59*4+5 = 241 mod 17 = 3

验证：<[6,12],[13,15]> = 78+180 = 258 mod 17 = 3 ✓
```

**第 2 轮：**

```
a = [6, 12], b = [13, 15], sum = 3, half = 1

c0 = 6*13 = 78 mod 17 = 10
c2 = (12-6)*(15-13) = 6*2 = 12
c1 = 3 - 2*10 - 12 = -29 mod 17 = 5

发送 c0=10, c2=12
假设 r2 = 6

fold(a,6): [6+6*(12-6)] = [42] = [8] (mod 17)
fold(b,6): [13+6*(15-13)] = [25] = [8] (mod 17)

sum = (12*6+5)*6+10 = 77*6+10 = 472 mod 17 = 13

验证：<[8],[8]> = 64 mod 17 = 13 ✓
```

**输出：**

- `evaluation_point = [4, 6]`
- `vector = [8]`, `covector = [8]`, `the_sum = 13`
- `last_fr_coords = [4, 6]`

---

### 步骤 6–9：无 STIR 轮，发送最终向量，PoW，开启 witness

同例子 1，略。

---

### 步骤 10：最终 sumcheck

`final_sumcheck: initial_size=1, num_rounds=0`，无操作。

---

### 最终返回值

```cpp
FinalClaim<F>{
    valid = true,
    evaluation_point = [4, 6],
    rlc_coefficients = [1, 7],      // initial_forms_rlc
    linear_form_rlc = 0              // F::zero()
}
```

---

### 这个例子的关键差异（对比例子 1）

| 变量 | 例子 1 | 例子 2 |
|------|--------|--------|
| `num_vectors` | 2 | 2 |
| `num_linear_forms` | 1 | 2 |
| witnesses 数 | 1 | 2 |
| OOD 补全 | 无需 | 需要发送 2 个跨承诺求值 |
| `constraint_rlc_coeffs` | [1, 7] | [1, 7, 15, 3] |
| `covector` 初始累积 | 1 项 | 2 项 |
| OOD 约束对 the_sum 的贡献 | 1 项 | 2 项 |

---

## 例子 3：包含一轮 STIR round 的完整流程

### 初始设置

使用 **GF(97)**（模 97 的整数，更大的域以容纳更多运算）。

**协议参数：**

- `initial_size = 8`（3 个变量）
- `num_vectors = 2`
- `num_linear_forms = 1`
- 1 个 witness 管理 2 个向量
- **1 轮 STIR**：`round_configs[0]` 的 `sumcheck.initial_size = 2, num_rounds = 1`
- 初始 sumcheck：`initial_size = 8, num_rounds = 2`（消耗 2 个变量，向量从 8→4→2）
- STIR sumcheck：`initial_size = 2, num_rounds = 1`（消耗 1 个变量，向量从 2→1）
- 最终 sumcheck：`initial_size = 1, num_rounds = 0`（无需折叠）

总变量消耗：2 + 1 = 3 = `num_vars` ✓

### 输入数据

```
vector[0] = [1, 2, 3, 4, 5, 6, 7, 8]
vector[1] = [9, 10, 11, 12, 13, 14, 15, 16]

linear_form[0] = Covector([1, 1, 1, 1, 1, 1, 1, 1])   // 求和

eval[0] = 1+2+...+8 = 36
eval[1] = 9+10+...+16 = 100 mod 97 = 3
```

**witness 构造：**

```
witness（管理 vector[0], vector[1]）:
  OOD 点 z=5
  5^0=1, 5^1=5, 5^2=25, 5^3=125 mod 97=28, 5^4=140 mod 97=43
  5^5=215 mod 97=21, 5^6=105 mod 97=8, 5^7=40

  v0_at_5 = 1*1 + 2*5 + 3*25 + 4*28 + 5*43 + 6*21 + 7*8 + 8*40
          = 1+10+75+112+215+126+56+320 = 915 mod 97 = 42

  v1_at_5 = 9*1 + 10*5 + 11*25 + 12*28 + 13*43 + 14*21 + 15*8 + 16*40
          = 9+50+275+336+559+294+120+640 = 2283 mod 97 = 52

  → out_of_domain.points = [5]
  → out_of_domain.matrix = [42, 52]（1 行 × 2 列）
```

---

### 步骤 1：补全跨承诺 OOD 求值

只有 1 个 witness 管理全部 2 个向量，无需补全。

```
oods_evals = [UE(5, 8)]
oods_matrix = [42, 52]
```

---

### 步骤 2：向量 RLC

```
vector_rlc_coeffs = geometric_challenge<F>(prover_state, 2)
  → 假设 α = 3 → [1, 3]

vector = [1,2,3,4,5,6,7,8] + 3*[9,10,11,12,13,14,15,16]
       = [1+27, 2+30, 3+33, 4+36, 5+39, 6+42, 7+45, 8+48]
       = [28, 32, 36, 40, 44, 48, 52, 56]
```

**输出：** `vector = [28, 32, 36, 40, 44, 48, 52, 56]`

---

### 步骤 3：约束 RLC

```
约束总数 = 1 + 1 = 2
constraint_rlc_coeffs = geometric_challenge<F>(prover_state, 2)
  → 假设 β = 7 → [1, 7]

initial_forms_rlc = [1]
oods_rlc = [7]

covector = [0]*8
lf[0] = Covector([1,1,1,1,1,1,1,1]).accumulate(covector, 1)
  → covector = [1,1,1,1,1,1,1,1]
```

---

### 步骤 4：计算 `the_sum`

```
the_sum = 0

i=0: row_sum = 1*36 + 3*3 = 36+9 = 45
     the_sum += 1 * 45 = 45

// OOD 累积
accumulate_many([UE(5,8)], covector, [7])
  covector[i] += 7 * 5^i (mod 97)
  5^0=1, 5^1=5, 5^2=25, 5^3=28, 5^4=43, 5^5=21, 5^6=8, 5^7=40

  covector = [1+7, 1+35, 1+175, 1+196, 1+301, 1+147, 1+56, 1+280]
           = [8, 36, 176, 197, 302, 148, 57, 281]
           mod 97: [8, 36, 79, 3, 11, 51, 57, 87]

i=0 (OOD): row_sum = 1*42 + 3*52 = 42+156 = 198 mod 97 = 4
     the_sum += 7 * 4 = 28
     the_sum = 45 + 28 = 73
```

**验证：** `<[28,32,36,40,44,48,52,56], [8,36,79,3,11,51,57,87]>`
= 28*8 + 32*36 + 36*79 + 40*3 + 44*11 + 48*51 + 52*57 + 56*87
= 224+1152+2844+120+484+2448+2964+4872 = 15108 mod 97 = 73 ✓

**输出：** `covector = [8, 36, 79, 3, 11, 51, 57, 87]`, `the_sum = 73`

---

### 步骤 5：初始 sumcheck

`initial_sumcheck: initial_size=8, num_rounds=2`

**第 1 轮（向量长度 8→4）：**

```
a = [28,32,36,40,44,48,52,56], b = [8,36,79,3,11,51,57,87], sum = 73, half = 4

c0 = 28*8 + 32*36 + 36*79 + 40*3
   = 224+1152+2844+120 = 4340 mod 97 = 4340-44*97 = 72

c2 = (44-28)*(11-8) + (48-32)*(51-36) + (52-36)*(57-79) + (56-40)*(87-3)
   = 16*3 + 16*15 + 16*(-22) + 16*84
   = 48+240-352+1344 = 1280 mod 97 = 19

c1 = 73 - 2*72 - 19 = -90 mod 97 = 7

发送 c0=72, c2=19
假设 r1 = 6

fold_pair(a, b, 6):
  a = [28+6*16, 32+6*16, 36+6*16, 40+6*16] = [124, 128, 132, 136]
    = [27, 31, 35, 39] (mod 97)
  b = [8+6*3, 36+6*15, 79+6*(-22), 3+6*84] = [26, 126, -53, 507]
    = [26, 29, 44, 22] (mod 97)

sum = (19*6+7)*6+72 = 121*6+72 = 798 mod 97 = 22

验证：<[27,31,35,39],[26,29,44,22]> = 702+899+1540+858 = 3999 mod 97 = 22 ✓
```

**第 2 轮（向量长度 4→2）：**

```
a = [27,31,35,39], b = [26,29,44,22], sum = 22, half = 2

c0 = 27*26 + 31*29 = 702+899 = 1601 mod 97 = 49
c2 = (35-27)*(44-26) + (39-31)*(22-29) = 8*18 + 8*(-7) = 144-56 = 88
c1 = 22 - 2*49 - 88 = -164 mod 97 = 30

发送 c0=49, c2=88
假设 r2 = 13

fold_pair(a, b, 13):
  a = [27+13*8, 31+13*8] = [131, 135] = [34, 38] (mod 97)
  b = [26+13*18, 29+13*(-7)] = [260, -62] = [66, 35] (mod 97)

sum = (88*13+30)*13+49 = 1174*13+49 = 15311 mod 97 = 82

验证：<[34,38],[66,35]> = 2244+1330 = 3574 mod 97 = 82 ✓
```

**输出：**

- `evaluation_point = [6, 13]`（初始 sumcheck 的 2 个坐标）
- `vector = [34, 38]`（长度 2）
- `covector = [66, 35]`（长度 2）
- `the_sum = 82`
- `last_fr_coords = [6, 13]`

---

### 步骤 6：逐轮 STIR（1 轮）

```
round_configs[0]:
  irs_committer: RS 编码 + Merkle 树承诺器
  sumcheck: initial_size = 2, num_rounds = 1
  pow: 工作量证明配置
```

#### 6a. IRS 承诺当前折叠向量

```
new_witness = irs_committer.commit(prover_state, {[34, 38]})
```

IRS 承诺过程：

1. 将 `[34, 38]` 进行 RS 编码（例如码率 1/2，编码后长度 4）
2. 构建 Merkle 树，发送根哈希
3. 选择 OOD 点，计算并发送 OOD 求值

假设 OOD 点 z=11：

```
v_at_11 = 34*1 + 38*11 = 34+418 = 452 mod 97 = 64
new_witness.out_of_domain.points = [11]
new_witness.out_of_domain.matrix = [64]
```

#### 6b. PoW

```
rc.pow.prove(prover_state, pow_engine_lookup)
// 工作量证明（mock：无操作）
```

#### 6c. 开启前一轮 witness（首轮：开启初始 witness）

```
is_first_round = true
→ 打开 initial_committer 的 witness
→ in_domain_src = initial_committer.open(prover_state, wptrs)
→ in_domain = lift(in_domain_src)
```

假设初始承诺的域内采样有 2 个点，p0=2, p1=7：

```
in_domain.points = [2, 7]
```

域内求值是对原始向量的 RS 编码值在这些点上的取值。`in_domain` 矩阵的列数为 `num_vectors * 2^(len(last_fr_coords))`，其中 `last_fr_coords = [6, 13]` 有 2 个坐标，所以每向量展开为 4 列，总计 8 列。

设 `in_domain.matrix`（2 行 × 8 列）为：

```
行 0 (p=2): [3, 7, 1, 5, 11, 2, 9, 4]
行 1 (p=7): [8, 6, 4, 2, 16, 14, 12, 10]
```

`is_first_round = false`

#### 6d. 收集 STIR 约束

**OOD 求值器：**

```
stir_challenges = new_witness.out_of_domain.evaluators(2)
  = [UE(11, 2)]   // 1 个 OOD 求值器，size = sumcheck.initial_size = 2
```

`UE(11, 2)` 表示向量 `[1, 11]`（即 `[11^0, 11^1]`）。

**域内求值器：**

```
in_domain_evals = in_domain.evaluators(2)
  = [UE(2, 2), UE(7, 2)]   // 2 个域内求值器
```

`UE(2, 2)` 表示 `[1, 2]`，`UE(7, 2)` 表示 `[1, 7]`。

```
stir_challenges = [UE(11,2), UE(2,2), UE(7,2)]   // 3 个约束
```

**OOD 值：**

```
stir_evaluations = new_witness.out_of_domain.values([1])   // weights = [1]
  = [dot([64], [1])] = [64]   // 1 个 OOD 值
```

**域内值（使用 tensor product 权重）：**

```
eq_w = MultilinearPoint([6, 13]).eq_weights()
  // eq(r, b) = Π_i (r_i * b_i + (1-r_i) * (1-b_i))
  // eq([6,13], 00) = (1-6)*(1-13) = (-5)*(-12) = 60
  // eq([6,13], 01) = (1-6)*13 = -65 mod 97 = 32
  // eq([6,13], 10) = 6*(1-13) = -72 mod 97 = 25
  // eq([6,13], 11) = 6*13 = 78
  eq_w = [60, 32, 25, 78]

tp = tensor_product([1, 3], [60, 32, 25, 78])
   = [1*60, 1*32, 1*25, 1*78, 3*60, 3*32, 3*25, 3*78]
   = [60, 32, 25, 78, 180, 96, 75, 234]
   mod 97: [60, 32, 25, 78, 83, 96, 75, 40]
```

`tp` 有 8 个元素 = `num_vectors(2) * 2^(len(last_fr_coords))(4) = 8`。

**域内值计算：**

```
in_domain_vals = in_domain.values(tp)
  = [dot(行0, tp), dot(行1, tp)]

行0 · tp = 3*60 + 7*32 + 1*25 + 5*78 + 11*83 + 2*96 + 9*75 + 4*40
         = 180+224+25+390+913+192+675+160 = 2759 mod 97 = 43

行1 · tp = 8*60 + 6*32 + 4*25 + 2*78 + 16*83 + 14*96 + 12*75 + 10*40
         = 480+192+100+156+1328+1344+900+400 = 4900 mod 97 = 50

in_domain_vals = [43, 50]

stir_evaluations = [64, 43, 50]   // OOD 值 + 域内值
```

**STIR RLC：**

```
stir_rlc = geometric_challenge<F>(prover_state, 3)
  → 假设 γ = 11 → [1, 11, 121 mod 97 = 24]
```

**累积 STIR 求值器到 covector：**

```
accumulate_many(stir_challenges=[UE(11,2), UE(2,2), UE(7,2)], covector, stir_rlc=[1, 11, 24])

covector 起始 = [66, 35]

UE(11,2) scalar=1:
  covector[0] += 1*11^0 = 1 → 67
  covector[1] += 1*11^1 = 11 → 46
  covector = [67, 46]

UE(2,2) scalar=11:
  covector[0] += 11*2^0 = 11 → 78
  covector[1] += 11*2^1 = 22 → 68
  covector = [78, 68]

UE(7,2) scalar=24:
  covector[0] += 24*7^0 = 24 → 102 mod 97 = 5
  covector[1] += 24*7^1 = 168 mod 97 = 71 → 139 mod 97 = 42
  covector = [5, 42]
```

**更新 the_sum：**

```
增量 = <vector, covector_new - covector_old>
     = <[34,38], [5-66, 42-35]>
     = <[34,38], [36, 7]>    // -61 mod 97 = 36
     = 34*36 + 38*7 = 1224+266 = 1490 mod 97 = 35

the_sum = 82 + 35 = 117 mod 97 = 20

验证：<vector, covector> = <[34,38], [5,42]> = 170+1596 = 1766 mod 97 = 20 ✓
```

---

#### 6e. STIR sumcheck

`rc.sumcheck: initial_size=2, num_rounds=1`

```
a = vector = [34, 38], b = covector = [5, 42], sum = 20, half = 1

c0 = 34*5 = 170 mod 97 = 73
c2 = (38-34)*(42-5) = 4*37 = 148 mod 97 = 51
c1 = 20 - 2*73 - 51 = -177 mod 97 = 17

发送 c0=73, c2=51
假设 r3 = 8

fold_pair(a, b, 8):
  a = [34 + 8*(38-34)] = [34+32] = [66]
  b = [5 + 8*(42-5)] = [5+296] = [301] = [301-3*97] = [10]

sum = (51*8+17)*8+73 = 425*8+73 = 3473 mod 97 = 78

验证：<[66],[10]> = 660 mod 97 = 78 ✓
```

**更新状态：**

```
evaluation_point = [6, 13, 8]   // 追加 STIR sumcheck 坐标
vector = [66]
covector = [10]
the_sum = 78
last_fr_coords = [8]

vector_rlc_coeffs = [1]   // 重置为单向量
```

**存储 witness：**

```
stored_round_witnesses.push_back(new_witness)
prev_round_witness = &stored_round_witnesses.back()
```

---

### 步骤 7：发送最终向量

```
vector = [66]，长度 = final_sumcheck.initial_size = 1 ✓
prover_state.prover_message(66)
```

---

### 步骤 8：最终 PoW

```
final_pow.prove(prover_state, pow_engine_lookup)
```

---

### 步骤 9：开启最终 witness

```
is_first_round = false（进入了 STIR 循环）
prev_round_witness != nullptr
→ 打开 round_configs.back() 的 witness
→ prev_rc.irs_committer.open(prover_state, {prev_round_witness})
→ 发送最后一轮 witness 的 Merkle 路径和域内求值
```

---

### 步骤 10：最终 sumcheck

```
final_sumcheck: initial_size = 1, num_rounds = 0
→ 无操作
→ evaluation_point 不变
```

---

### 最终返回值

```cpp
FinalClaim<F>{
    valid = true,
    evaluation_point = [6, 13, 8],      // 3 个坐标：2 来自初始 sumcheck + 1 来自 STIR sumcheck
    rlc_coefficients = [1],             // initial_forms_rlc
    linear_form_rlc = 0                 // F::zero()
}
```

---

### 这个例子对应代码中的关键变量

| 变量 | 值 | 说明 |
|------|-----|------|
| `num_vectors` | 2 | |
| `num_linear_forms` | 1 | |
| `vector_rlc_coeffs` | [1, 3] → [1] | STIR 后重置为 [1] |
| `constraint_rlc_coeffs` | [1, 7] | |
| `oods_evals` | [UE(5,8)] | 1 个 OOD 求值器 |
| `oods_matrix` | [42, 52] | |
| `vector` | [66] | 最终折叠至长度 1 |
| `covector` | [10] | |
| `the_sum` | 78 | |
| `evaluation_point` | [6, 13, 8] | 所有折叠坐标拼接 |
| `last_fr_coords` | [8] | 最后一轮（STIR）的坐标 |
| `stored_round_witnesses` | [new_witness] | 1 个 STIR 轮 witness |
| `prev_round_witness` | 指向 stored_round_witnesses[0] | |

---

### STIR 轮的完整数据流图

```
步骤 5 输出:
  vector = [34, 38], covector = [66, 35], the_sum = 82
  evaluation_point = [6, 13]
  last_fr_coords = [6, 13]

        ┌─────────────────────────────────────────┐
        │           步骤 6: STIR 轮 0              │
        │                                         │
  6a.   │  IRS commit([34, 38])                   │
        │  → new_witness (OOD: z=11, val=64)      │
        │                                         │
  6b.   │  PoW                                    │
        │                                         │
  6c.   │  Open initial witness                   │
        │  → in_domain (域点 2, 7)                 │
        │                                         │
  6d.   │  STIR 约束收集:                          │
        │    stir_challenges = [UE(11,2),          │
        │                       UE(2,2), UE(7,2)]  │
        │    stir_evaluations = [64, 43, 50]       │
        │    stir_rlc = [1, 11, 24]                │
        │    covector: [66,35] → [5, 42]           │
        │    the_sum: 82 → 20                      │
        │                                         │
  6e.   │  STIR sumcheck (initial_size=2, 1 轮):   │
        │    c0=73, c2=51, r3=8                    │
        │    vector → [66], covector → [10]         │
        │    the_sum → 78                           │
        │    evaluation_point += [8]                │
        │    last_fr_coords = [8]                   │
        │    vector_rlc_coeffs = [1]                │
        └─────────────────────────────────────────┘

步骤 7: 发送 vector[0] = 66
步骤 8: 最终 PoW
步骤 9: 开启最终 witness (prev_round_witness)
步骤 10: 最终 sumcheck (0 轮)

返回: FinalClaim{ep=[6,13,8], rlc=[1], lf_rlc=0}
```

---

## 代码拼写问题

**`whir_prover.hpp` 第 99 行：**

```cpp
auto w_evals = witness.out_of_d   omain.evaluators(initial_size());
```

这里 `out_of_d   omain` 中间有多余空格，应该是 `out_of_domain`。这在 C++ 中会导致编译错误（`d` 和 `omain` 被解析为两个独立的标识符）。应修正为：

```cpp
auto w_evals = witness.out_of_domain.evaluators(initial_size());
```
