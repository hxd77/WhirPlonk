# WHIR IRS 承诺协议完整运行例子

本文档基于 `irs_commit.hpp` 中的交错 Reed-Solomon 承诺协议，生成 3 个难度递增的完整运行例子。

---

## 例子 1：唯一解码模式，单个向量

### 一、参数设置

| 参数 | 值 | 说明 |
|------|-----|------|
| `security_target` | 128（比特） | 目标安全级别 |
| `unique_decoding` | `true` | 唯一解码，无 Johnson 松弛 |
| `num_vectors` | 1 | 单个向量 |
| `vector_size` | 8 | 向量长度（系数个数） |
| `interleaving_depth` | 1 | 无交错 |
| `rate` | 0.5 | 码率 = message_length / codeword_length |
| `message_length` | 8 | = vector_size / interleaving_depth = 8/1 |
| `codeword_length` | 16 | = ceil(8 / 0.5) |
| `num_cols` | 1 | = num_vectors × interleaving_depth = 1×1 |
| `in_domain_samples` | 3 | 域内查询次数（简化值） |
| `out_domain_samples` | 0 | 唯一解码不需要域外采样 |
| `johnson_slack` | 0.0 | 唯一解码无松弛 |
| `deduplicate_in_domain` | `false` | 不去重 |

**为什么唯一解码没有 OOD 采样？**
唯一解码模式下，RS 码的最小距离保证了：如果编码距离 ≤ (1-rate)/2 = 0.25，存在唯一最近码字。因此不需要域外采样来区分多个候选码字——域内查询本身就足以检测作弊。`out_domain_samples = 0` 和 `johnson_slack = 0` 共同标识唯一解码模式（见代码 `unique_decoding()` 函数）。

---

### 二、输入向量

```
v0 = [1, 2, 3, 4, 5, 6, 7, 8]
```

这是一个 GF(p) 上的 8 维向量，代表多项式 `P(x) = 1 + 2x + 3x² + ... + 8x⁷` 的系数。

---

### 三、commit 阶段完整模拟

#### 3.1 交错 RS 编码 (`interleaved_rs_encode`)

由于 `interleaving_depth = 1`，每个向量不被切分，直接作为一个完整消息。

**步骤 1：零填充**

```
消息 = [1, 2, 3, 4, 5, 6, 7, 8]   （message_length = 8）
零填充到 codeword_length = 16:
缓冲区 = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
```

**步骤 2：正向 NTT（求值）**

假设使用 16 次单位根 ω（在实际代码中由 `ntt::generator<Source>(codeword_length)` 提供），对缓冲区执行 NTT：

```
NTT([1,2,3,4,5,6,7,8,0,0,0,0,0,0,0,0]) = [c₀, c₁, c₂, ..., c₁₅]
```

其中 `cᵢ = P(ωⁱ) = Σⱼ coeff[j] · ωⁱʲ`。

为具体演示，假设计算结果为：

```
c₀=36, c₁=5, c₂=12, c₃=8, c₄=3, c₅=14, c₆=7, c₇=11,
c₈=2, c₉=9, c₁₀=6, c₁₁=13, c₁₂=4, c₁₃=10, c₁₄=15, c₁₅=1
```

（所有运算 mod p；这里用占位值演示结构）

**步骤 3：转置为行主序**

由于只有 1 个多项式和 1 个交错深度，转置是平凡的：

```
matrix (16 行 × 1 列) = [
  行 0:  [c₀]  = [36]
  行 1:  [c₁]  = [5]
  行 2:  [c₂]  = [12]
  ...
  行 15: [c₁₅] = [1]
]
```

**代码变量：** `matrix` 是一个平坦的 `std::vector<Source>`，长度 = `codeword_length × num_cols = 16 × 1 = 16`。

#### 3.2 逐行哈希 (`commit_leaves`)

对 matrix 的每一行执行：LE 编码 → 哈希。

```
行 0: encode([36]) → [36_le_bytes] → H([36_le_bytes]) → leaf₀
行 1: encode([5])  → [5_le_bytes]  → H([5_le_bytes])  → leaf₁
...
行 15: encode([1]) → [1_le_bytes]  → H([1_le_bytes])  → leaf₁₅
```

每个 `leafᵢ` 是一个 32 字节的哈希值。对于 Goldilocks 域，每个元素编码为 8 字节小端序。

**代码变量：** `leaves` 是 `std::vector<Hash>`，长度 = `codeword_length = 16`。

#### 3.3 Merkle 树承诺 (`merkle_tree::commit`)

从 16 个叶子构建二叉 Merkle 树：

```
                    root (H₀₁₅)
                   /            \
          H₀₋₇                    H₈₋₁₅
         /      \                /       \
     H₀₋₃     H₄₋₇         H₈₋₁₁    H₁₂₋₁₅
    /    \    /    \        /    \     /     \
  H₀₁  H₂₃ H₄₅  H₆₇   H₈₉  H₁₀₁₁ H₁₂₁₃ H₁₄₁₅
  / \  / \  / \  / \    / \   / \   / \   / \
 l₀ l₁ l₂ l₃ l₄ l₅ l₆ l₇ l₈ l₉ l₁₀ l₁₁ l₁₂ l₁₃ l₁₄ l₁₅
```

内部节点计算方式：`Hᵢⱼ = H(leafᵢ || leafⱼ)`（64 字节输入，32 字节输出）。

**代码调用：**
```cpp
mt_witness = merkle_tree::commit(prover_state, matrix_commit_mt, leaves, engine_lookup);
```

`prover_state.prover_message(root)` 将根哈希发送给验证者（通过 Fiat-Shamir transcript）。

#### 3.4 域外采样

由于 `out_domain_samples = 0`，跳过此步骤。证明者不发送任何 OOD 求值。

**代码：** `oods_points = prover_state.verifier_message_vec<Target>(0)` 返回空向量。

#### 3.5 输出 Witness

```cpp
Witness {
    matrix = [36, 5, 12, 8, 3, 14, 7, 11, 2, 9, 6, 13, 4, 10, 15, 1],  // 16×1
    matrix_witness = { nodes = [l₀, l₁, ..., l₁₅, H₀₁, H₂₃, ..., root] },  // 完整 Merkle 树
    matrix_leaves = [leaf₀, leaf₁, ..., leaf₁₅],  // 叶子哈希副本
    out_of_domain = { points = [], matrix = [] }  // 空
}
```

---

### 四、receive_commitment 阶段

验证者执行 `receive_commitment(verifier_state)`，从 transcript 获取：

```
1. Merkle 根哈希 root（由 merkle_tree::receive_commitment 读取）
2. OOD 点：verifier_message_vec<Target>(0) → 空（无域外采样）
3. OOD 矩阵：无
```

**验证者不需要保存完整编码矩阵。** 它只保存：
- `Commitment.matrix_commitment = { root }` — Merkle 根
- `Commitment.out_of_domain = { points=[], matrix=[] }` — 空

这是 IRS 承诺的核心优势：验证者空间为 O(1)，而非 O(codeword_length × num_cols)。

---

### 五、open 阶段完整模拟

#### 5.1 生成域内挑战 (`in_domain_challenges`)

```cpp
auto [indices, points] = in_domain_challenges(prover_state);
```

**步骤 1：从 transcript 挤压随机索引**

```
codeword_length = 16, in_domain_samples = 3
size_bytes = ceil(log₂(16) / 8) = ceil(4/8) = 1 字节/索引

从 transcript 挤压 3 字节：假设为 [0xAB, 0x3F, 0x7C]
  index₀ = 0xAB mod 16 = 171 mod 16 = 11
  index₁ = 0x3F mod 16 = 63 mod 16 = 15
  index₂ = 0x7C mod 16 = 124 mod 16 = 12

indices = [11, 15, 12]
```

**步骤 2：索引 → NTT 域点**

```
假设 generator g = 3（16 次单位根）
  points[0] = g^11 = 3^11 mod p
  points[1] = g^15 = 3^15 mod p
  points[2] = g^12 = 3^12 mod p
```

这些点对应编码矩阵中第 11、15、12 行的求值点。验证者和证明者通过相同的 Fiat-Shamir transcript 得到相同的 indices 和 points。

#### 5.2 提取被挑战的行

对每个被挑战的索引，从 `witness.matrix` 中提取对应行：

```
row_11 = matrix[11 * num_cols .. 11 * num_cols + num_cols]
       = matrix[11..12] = [13]   （第 11 行，1 列）

row_15 = matrix[15 * num_cols .. 15 * num_cols + num_cols]
       = matrix[15..16] = [1]

row_12 = matrix[12 * num_cols .. 12 * num_cols + num_cols]
       = matrix[12..13] = [4]
```

**子矩阵（prover_hint）：**
```
submatrix = [13, 1, 4]   （3 行 × 1 列 = 3 个元素）
```

**代码：**
```cpp
prover_state.prover_hint(submatrix);  // 发送子矩阵原始数据
```

#### 5.3 Merkle 树打开 (`merkle_tree::open`)

对 indices = [11, 15, 12] 排序后为 [11, 12, 15]。

**自底向上生成兄弟哈希提示：**

```
第 0 层（叶子层，16 个节点）:
  indices = [11, 12, 15]

  11 (奇数): 兄弟 = 11^1 = 10 → 提示 H(leaf₁₀)
  12 (偶数): 兄弟 = 12^1 = 13 → 但 13 不在集合中 → 提示 H(leaf₁₃)
  15 (奇数): 兄弟 = 15^1 = 14 → 提示 H(leaf₁₄)

  配对: {10→父5, 11→父5, 12→父6, 13→父6, 14→父7, 15→父7}
  父层索引: [5, 6, 7]

第 1 层（8 个节点）:
  indices = [5, 6, 7]

  5 (奇数): 兄弟 = 4 → 提示 H(node₄)
  6 (偶数): 兄弟 = 7 → 7 在集合中 → 无需提示
  → 配对: {4→父2, 5→父2, 6→父3, 7→父3}
  父层索引: [2, 3]

第 2 层（4 个节点）:
  indices = [2, 3]

  2 (偶数): 兄弟 = 3 → 3 在集合中 → 无需提示
  → 配对: {2→父1, 3→父1}
  父层索引: [1]

第 3 层（2 个节点）:
  indices = [1]

  1 (奇数): 兄弟 = 0 → 提示 H(node₀)
  → 父层索引: [0]（根）
```

**发送的提示：** `[H(leaf₁₀), H(leaf₁₃), H(leaf₁₄), H(node₄), H(node₀)]` — 共 5 个哈希。

**代码：**
```cpp
merkle_tree::open(prover_state, matrix_commit_mt, witness.matrix_witness, indices);
// 内部调用 open_path 生成 hints，然后逐个 prover_hint(h) 发送
```

---

### 六、verify 阶段完整模拟

#### 6.1 挤压相同的挑战索引

```cpp
auto [indices, points] = in_domain_challenges(verifier_state);
// 与证明者得到相同的 indices = [11, 15, 12], points = [g^11, g^15, g^12]
```

#### 6.2 接收子矩阵提示

```cpp
std::vector<Source> submatrix;
verifier_state.prover_hint(submatrix);
// submatrix = [13, 1, 4]   （3 行 × 1 列）
```

#### 6.3 重新计算叶子哈希 (`commit_leaves`)

验证者用接收到的子矩阵重新计算叶子哈希：

```
leaf₁₁ = H(encode([13]))   // 对 submatrix 第 0 行
leaf₁₅ = H(encode([1]))    // 对 submatrix 第 1 行
leaf₁₂ = H(encode([4]))    // 对 submatrix 第 2 行
```

如果证明者篡改了任何一行的数据（例如把 13 改成 14），重新计算的哈希将与原始承诺不同。

#### 6.4 Merkle 树验证 (`merkle_tree::verify`)

验证者从 transcript 读取兄弟提示，自底向上重建根：

```
第 0 层重建:
  读取提示 H(leaf₁₀), H(leaf₁₃), H(leaf₁₄)
  节点 10 = H(leaf₁₀), 节点 11 = leaf₁₁（重新计算）
  节点 12 = leaf₁₂（重新计算），节点 13 = H(leaf₁₃)
  节点 14 = H(leaf₁₄), 节点 15 = leaf₁₅（重新计算）

  父节点 5 = H(node₁₀ || node₁₁)
  父节点 6 = H(node₁₂ || node₁₃)
  父节点 7 = H(node₁₄ || node₁₅)

第 1 层重建:
  读取提示 H(node₄)
  父节点 2 = H(node₄ || node₅)
  父节点 3 = H(node₆ || node₇)

第 2 层重建:
  无需额外提示（节点 2 和 3 都已知）
  父节点 1 = H(node₂ || node₃)

第 3 层重建:
  读取提示 H(node₀)
  根' = H(node₀ || node₁)

比较: root' == root（来自 Commitment）
```

**如果 submatrix 被篡改：** 假设证明者将 `submatrix[0]` 从 13 改为 14：
- `leaf₁₁' = H(encode([14])) ≠ leaf₁₁`
- → `node₁₁' ≠ node₁₁`
- → `node₅' ≠ node₅`
- → `node₂' ≠ node₂`
- → `node₁' ≠ node₁`
- → `root' ≠ root` → 验证失败 ✓

---

### 七、最终结果

```
prover open 返回的 Evaluations<Source>:
  points = [g^11, g^15, g^12]    （3 个 NTT 域点）
  matrix = [13, 1, 4]            （3 行 × 1 列）

verifier verify 返回的 Evaluations<Source>:
  points = [g^11, g^15, g^12]    （相同，来自相同的 transcript）
  matrix = [13, 1, 4]            （来自 prover_hint）

二者 points 是否一致：✓（确定性挤压）
二者 matrix 是否一致：✓（prover_hint 直接传递）
本例验证是否通过：✓（Merkle 根匹配）
```

---

### 这个例子对应代码中的哪些函数

| 函数 | 文件位置 | 作用 |
|------|----------|------|
| `Config::from_params()` | irs_commit.hpp:266 | 从安全参数构造 Config |
| `Config::commit()` | irs_commit.hpp:343 | 编码 + Merkle 承诺 + OOD 求值 |
| `interleaved_rs_encode()` | mod_ntt.hpp:50 | 交错 RS 编码（NTT） |
| `commit_leaves()` | matrix_commit.hpp:170 | 逐行 LE 编码 + 哈希 |
| `merkle_tree::commit()` | merkle_tree.hpp:328 | 构建 Merkle 树 + 发送根 |
| `Config::receive_commitment()` | irs_commit.hpp:456 | 验证者接收承诺 |
| `Config::in_domain_challenges()` | irs_commit.hpp:483 | 挤压域内挑战索引 |
| `challenge_indices()` | challenge_indices.hpp:97 | 拒绝采样生成索引 |
| `Config::open()` | irs_commit.hpp:519 | 提取行 + Merkle 打开 |
| `merkle_tree::open()` | merkle_tree.hpp:354 | 发送兄弟提示 |
| `Config::verify()` | irs_commit.hpp:601 | 接收子矩阵 + 验证 Merkle |
| `merkle_tree::verify()` | merkle_tree.hpp:453 | 从提示重建根并比较 |
| `Evaluations::num_points()` | irs_commit.hpp:88 | 求值点数量 |
| `Evaluations::num_columns()` | irs_commit.hpp:91 | 每行列数 |
| `Evaluations::values()` | irs_commit.hpp:114 | 逐行加权内积 |

---

## 例子 2：列表解码模式，单个向量，有域外采样

### 一、参数设置

| 参数 | 值 | 说明 |
|------|-----|------|
| `security_target` | 128（比特） | 目标安全级别 |
| `unique_decoding` | `false` | 列表解码 |
| `num_vectors` | 1 | 单个向量 |
| `vector_size` | 8 | 向量长度 |
| `interleaving_depth` | 1 | 无交错 |
| `rate` | 0.25 | 码率 = 1/4 |
| `message_length` | 8 | = 8/1 |
| `codeword_length` | 32 | = ceil(8 / 0.25) |
| `num_cols` | 1 | = 1×1 |
| `in_domain_samples` | 4 | 域内查询次数（简化值） |
| `out_domain_samples` | 2 | 域外采样次数 |
| `johnson_slack` | √0.25/20 = 0.025 | Johnson 松弛量 η |
| `deduplicate_in_domain` | `false` | |

**关键概念解释：**

- **`johnson_slack = √rate / 20`**：Johnson 界松弛量。在列表解码中，允许的相对距离从唯一解码的 `(1-rate)/2` 扩展到 `1 - √rate`，但需要一个松弛量 η 来保证列表大小有限。η 越小，列表越大，安全性分析越复杂。

- **`list_size() = 1 / (2·η·√rate) = 1 / (2·0.025·0.5) = 40`**：列表大小上界。含义是：在最坏情况下，可能存在最多 40 个码字都在距离界内。域外采样用于将这些候选码字区分到只剩 1 个。

- **`rbr_ood_sample(field_bits)`**：每轮域外采样的安全性。每个 OOD 点提供 `field_bits - log₂(vector_size-1)` 比特的安全性，乘以 `out_domain_samples` 轮，再减去 `log₂(L choose 2)` 的列表区分代价。

- **`rbr_queries()`**：每轮域内查询的安全性。每个查询提供 `-log₂(√rate + η)` 比特安全性。

---

### 二、输入向量

```
v0 = [1, 2, 3, 4, 5, 6, 7, 8]
```

---

### 三、commit 阶段完整模拟

#### 3.1 交错 RS 编码

```
消息 = [1, 2, 3, 4, 5, 6, 7, 8]   （message_length = 8）
零填充到 codeword_length = 32:
缓冲区 = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, ..., 0]   （32 个元素）

NTT 求值 → 32 个码字符号
matrix (32 行 × 1 列) = [c₀, c₁, c₂, ..., c₃₁]
```

由于 rate = 1/4，码字中只有 25% 是"信息位"，其余是"冗余位"。这提供了更强的纠错能力：可以容忍高达 `(1 - √0.25) = 50%` 的相对距离（列表解码界），而唯一解码只能容忍 `(1-0.25)/2 = 37.5%`。

#### 3.2 逐行哈希

```
leaf₀ = H(encode([c₀]))
leaf₁ = H(encode([c₁]))
...
leaf₃₁ = H(encode([c₃₁]))
```

32 个叶子哈希。

#### 3.3 Merkle 树承诺

```
构建 5 层 Merkle 树（32 个叶子 → 2^5）
root = H(...)   // 通过 prover_state.prover_message(root) 发送
```

#### 3.4 域外采样（本例的关键差异！）

```cpp
auto oods_points = prover_state.template verifier_message_vec<Target>(out_domain_samples);
// out_domain_samples = 2
// verifier_message_vec 从 transcript 挤压 2 个随机扩域点
// 假设得到: oods_points = [z₁, z₂]
```

**`verifier_message_vec<Target>(2)` 做了什么？**

从 Fiat-Shamir transcript 中挤压 2 个 `Target`（扩域）元素。这与 `verifier_message<F>()` 类似，但返回的是扩域元素。扩域点的选择保证了：即使证明者知道了承诺，也无法预测 OOD 点（因为它们依赖于 transcript 状态）。

**对每个 OOD 点，对原始向量求值：**

```cpp
for (const auto& point : oods_points) {        // z₁, z₂
    for (const auto& vec : vectors) {            // v0
        Target value = mixed_univariate_evaluate<M>(embedding_val, vec, point);
        prover_state.prover_message(value);      // 发送求值结果
        oods_matrix.push_back(value);
    }
}
```

**`mixed_univariate_evaluate` 做了什么？**

这是关键函数。它不是对编码后的码字求值，而是对**原始多项式系数**在扩域点处求值：

```
P(z) = Σⱼ emb(coeff[j]) · zʲ
```

其中 `emb` 是基域→扩域的嵌入映射。对于 `Identity` 映射，就是简单的 `coeff[j]`。

```
P(z₁) = 1·z₁⁰ + 2·z₁¹ + 3·z₁² + ... + 8·z₁⁷   （在扩域中计算）
P(z₂) = 1·z₂⁰ + 2·z₂¹ + 3·z₂² + ... + 8·z₂⁷
```

**为什么 OOD 求值检测作弊？**

如果证明者提交的不是合法码字（例如，修改了某个编码值），那么：
- 域内查询可能碰巧通过（如果被挑战的行恰好没被改）
- 但域外求值会暴露不一致：修改后的码字对应的"隐含多项式"在 OOD 点的求值，与证明者发送的值不一致

#### 3.5 输出 Witness

```cpp
Witness {
    matrix = [c₀, c₁, ..., c₃₁],     // 32×1
    matrix_witness = { nodes = [...] }, // 完整 Merkle 树
    matrix_leaves = [leaf₀, ..., leaf₃₁],
    out_of_domain = {
        points = [z₁, z₂],              // 2 个扩域点
        matrix = [P(z₁), P(z₂)]         // 2 个扩域值
    }
}
```

---

### 四、receive_commitment 阶段

验证者执行 `receive_commitment(verifier_state)`：

```
1. 接收 Merkle 根 root
2. 挤压 OOD 点: verifier_message_vec<Target>(2) → [z₁, z₂]
   （与证明者得到相同的点，因为 transcript 状态同步）
3. 读取 OOD 求值: prover_message(val) → [P(z₁), P(z₂)]
```

**为什么验证者要重新挤压相同的 OOD 点？**

验证者必须知道 OOD 点才能在后续验证中检查求值的一致性。由于使用 Fiat-Shamir，证明者和验证者通过相同的 transcript 状态得到相同的随机点。这保证了：
- 证明者不能预先选择对自己有利的 OOD 点
- 验证者可以在后续步骤中独立验证求值的正确性

**验证者输出：**

```cpp
Commitment {
    matrix_commitment = { root },
    out_of_domain = {
        points = [z₁, z₂],
        matrix = [P(z₁), P(z₂)]    // 从 transcript 读取
    }
}
```

---

### 五、open 阶段完整模拟

#### 5.1 生成域内挑战

```
codeword_length = 32, in_domain_samples = 4
size_bytes = ceil(log₂(32) / 8) = ceil(5/8) = 1 字节/索引

从 transcript 挤压 4 字节：假设 [0x1A, 0x3B, 0x7F, 0xC2]
  index₀ = 0x1A mod 32 = 26
  index₁ = 0x3B mod 32 = 59 mod 32 = 27
  index₂ = 0x7F mod 32 = 127 mod 32 = 31
  index₃ = 0xC2 mod 32 = 194 mod 32 = 2

indices = [26, 27, 31, 2]

generator g = 32 次单位根
points = [g^26, g^27, g^31, g^2]
```

#### 5.2 提取被挑战行 + Merkle 打开

```
submatrix = [c₂₆, c₂₇, c₃₁, c₂]   // 4 行 × 1 列

prover_state.prover_hint(submatrix);
merkle_tree::open(prover_state, matrix_commit_mt, witness.matrix_witness, indices);
```

---

### 六、verify 阶段完整模拟

与例子 1 类似：

```
1. 挤压相同的 indices = [26, 27, 31, 2]
2. 接收 submatrix = [c₂₆, c₂₇, c₃₁, c₂]
3. 重新计算叶子哈希: leaf₂₆, leaf₂₇, leaf₃₁, leaf₂
4. 从 transcript 读取 Merkle 提示
5. 自底向上重建根，与 Commitment.root 比较
```

---

### 七、最终结果

```
prover open 返回的 Evaluations<Source>:
  points = [g^26, g^27, g^31, g^2]
  matrix = [c₂₆, c₂₇, c₃₁, c₂]   （4×1）

verifier verify 返回的 Evaluations<Source>:
  points = [g^26, g^27, g^31, g^2]
  matrix = [c₂₆, c₂₇, c₃₁, c₂]

二者一致：✓
验证通过：✓
```

**OOD 求值在 WHIR 协议中的角色：** 在 WHIR 的 STIR 折叠中，每一轮的 `open` 返回域内求值，而 `out_of_domain` 提供域外求值。这两类求值共同构成 STIR 约束，用于验证折叠后向量的一致性。列表解码模式下，OOD 采样是安全性的必要组成部分。

---

### 这个例子对应代码中的哪些函数

| 函数 | 作用 |
|------|------|
| `Config::from_params()` | 计算 johnson_slack, out_domain_samples, in_domain_samples |
| `Config::commit()` | 编码 + Merkle + OOD 求值 |
| `verifier_message_vec<Target>()` | 从 transcript 挤压 OOD 扩域点 |
| `mixed_univariate_evaluate()` | 对原始向量在扩域点处求值 |
| `prover_state.prover_message(value)` | 发送 OOD 求值结果 |
| `Config::receive_commitment()` | 接收 Merkle 根 + OOD 点 + OOD 值 |
| `Config::open()` | 域内打开 |
| `Config::verify()` | 域内验证 |
| `Config::list_size()` | 列表大小上界 |
| `Config::rbr_ood_sample()` | OOD 采样安全性 |
| `Config::rbr_queries()` | 域内查询安全性 |

---

## 例子 3：多个向量 + 交错深度

### 一、参数设置

| 参数 | 值 | 说明 |
|------|-----|------|
| `security_target` | 128（比特） | |
| `unique_decoding` | `true` | 唯一解码 |
| `num_vectors` | 2 | 两个向量 |
| `vector_size` | 8 | 每个向量 8 个系数 |
| `interleaving_depth` | 2 | 交错深度为 2 |
| `rate` | 0.5 | 码率 |
| `message_length` | 4 | = vector_size / interleaving_depth = 8/2 |
| `codeword_length` | 8 | = ceil(4 / 0.5) |
| `num_cols` | 4 | = num_vectors × interleaving_depth = 2×2 |
| `in_domain_samples` | 3 | |
| `out_domain_samples` | 0 | 唯一解码 |
| `deduplicate_in_domain` | `false` | |

**为什么 `num_cols = num_vectors × interleaving_depth`？**

每个向量被切分为 `interleaving_depth` 个子块，每个子块独立编码为一个长度为 `codeword_length` 的码字。所有向量的所有子块的码字被**交错排列**在同一矩阵的列中。

所以列数 = 向量数 × 每个向量的子块数 = `num_vectors × interleaving_depth`。

**为什么编码矩阵列数会变多？**

交错的目的是降低每个子块的消息长度，从而降低单次 NTT 的规模。对于 `vector_size = 8, interleaving_depth = 2`：
- 不交错：NTT 规模 = 8（或更大，取决于码率）
- 交错后：每次 NTT 规模 = 4，但需要 2×2 = 4 次 NTT

这在 GPU 并行场景下更有利：4 个小 NTT 可以更好地利用 GPU 的并行性。

---

### 二、输入向量

```
v0 = [1, 2, 3, 4, 5, 6, 7, 8]
v1 = [9, 10, 11, 12, 13, 14, 15, 16]
```

---

### 三、commit 阶段完整模拟

#### 3.1 交错 RS 编码 (`interleaved_rs_encode`)

**步骤 1：切分 + 零填充**

对每个向量，按 `interleaving_depth = 2` 切分为 2 个子块，每个子块长度 = `message_length = 4`。

```
v0 = [1, 2, 3, 4, 5, 6, 7, 8]
  block_0_0 = [1, 2, 3, 4]   （前 4 个系数）
  block_0_1 = [5, 6, 7, 8]   （后 4 个系数）

v1 = [9, 10, 11, 12, 13, 14, 15, 16]
  block_1_0 = [9, 10, 11, 12]
  block_1_1 = [13, 14, 15, 16]
```

零填充到 `codeword_length = 8`：

```
buffer_0_0 = [1, 2, 3, 4, 0, 0, 0, 0]
buffer_0_1 = [5, 6, 7, 8, 0, 0, 0, 0]
buffer_1_0 = [9, 10, 11, 12, 0, 0, 0, 0]
buffer_1_1 = [13, 14, 15, 16, 0, 0, 0, 0]
```

**步骤 2：正向 NTT**

对每个缓冲区执行 8 点 NTT：

```
ntt_0_0 = NTT([1,2,3,4,0,0,0,0])   = [a₀, a₁, a₂, a₃, a₄, a₅, a₆, a₇]
ntt_0_1 = NTT([5,6,7,8,0,0,0,0])   = [b₀, b₁, b₂, b₃, b₄, b₅, b₆, b₇]
ntt_1_0 = NTT([9,10,11,12,0,0,0,0]) = [d₀, d₁, d₂, d₃, d₄, d₅, d₆, d₇]
ntt_1_1 = NTT([13,14,15,16,0,0,0,0]) = [e₀, e₁, e₂, e₃, e₄, e₅, e₆, e₇]
```

为具体演示，假设（用 GF(17) 的 8 次单位根 g=9 计算）：

```
ntt_0_0 = [10, 3, 8, 12, 6, 14, 9, 5]     // P₀₀(gⁱ)
ntt_0_1 = [9, 7, 2, 11, 13, 4, 15, 6]      // P₀₁(gⁱ)
ntt_1_0 = [15, 8, 4, 13, 1, 10, 6, 3]      // P₁₀(gⁱ)
ntt_1_1 = [14, 5, 11, 2, 8, 15, 7, 9]      // P₁₁(gⁱ)
```

**步骤 3：转置为行主序**

```
matrix (8 行 × 4 列):

行 0: [ntt_0_0[0], ntt_0_1[0], ntt_1_0[0], ntt_1_1[0]] = [10, 9, 15, 14]
行 1: [ntt_0_0[1], ntt_0_1[1], ntt_1_0[1], ntt_1_1[1]] = [3, 7, 8, 5]
行 2: [ntt_0_0[2], ntt_0_1[2], ntt_1_0[2], ntt_1_1[2]] = [8, 2, 4, 11]
行 3: [ntt_0_0[3], ntt_0_1[3], ntt_1_0[3], ntt_1_1[3]] = [12, 11, 13, 2]
行 4: [ntt_0_0[4], ntt_0_1[4], ntt_1_0[4], ntt_1_1[4]] = [6, 13, 1, 8]
行 5: [ntt_0_0[5], ntt_0_1[5], ntt_1_0[5], ntt_1_1[5]] = [14, 4, 10, 15]
行 6: [ntt_0_0[6], ntt_0_1[6], ntt_1_0[6], ntt_1_1[6]] = [9, 15, 6, 7]
行 7: [ntt_0_0[7], ntt_0_1[7], ntt_1_0[7], ntt_1_1[7]] = [5, 6, 3, 9]
```

**每一行包含什么？**

行 `i` 包含第 `i` 个求值点（即 `gⁱ`）在所有 4 个子多项式上的求值结果：
- 列 0：`v0` 的第 0 个子块在 `gⁱ` 处的值
- 列 1：`v0` 的第 1 个子块在 `gⁱ` 处的值
- 列 2：`v1` 的第 0 个子块在 `gⁱ` 处的值
- 列 3：`v1` 的第 1 个子块在 `gⁱ` 处的值

**代码变量：** `matrix` 是平坦数组，长度 = `codeword_length × num_cols = 8 × 4 = 32`。

#### 3.2 逐行哈希

```
leaf₀ = H(encode([10, 9, 15, 14]))   // 行 0，4 个元素，每个 8 字节 → 32 字节输入
leaf₁ = H(encode([3, 7, 8, 5]))
...
leaf₇ = H(encode([5, 6, 3, 9]))
```

8 个叶子哈希。

#### 3.3 Merkle 树承诺

```
构建 3 层 Merkle 树（8 个叶子 → 2³）
root = H(...)
```

#### 3.4 域外采样

`out_domain_samples = 0`，跳过。

#### 3.5 输出 Witness

```cpp
Witness {
    matrix = [10,9,15,14, 3,7,8,5, 8,2,4,11, 12,11,13,2, 6,13,1,8, 14,4,10,15, 9,15,6,7, 5,6,3,9],
    matrix_witness = { nodes = [...] },
    matrix_leaves = [leaf₀, ..., leaf₇],
    out_of_domain = { points = [], matrix = [] }
}
```

---

### 四、receive_commitment 阶段

```
1. 接收 Merkle 根 root
2. OOD 点：空
3. OOD 矩阵：空

Commitment {
    matrix_commitment = { root },
    out_of_domain = { points = [], matrix = [] }
}
```

---

### 五、open 阶段完整模拟

#### 5.1 生成域内挑战

```
codeword_length = 8, in_domain_samples = 3
size_bytes = ceil(log₂(8) / 8) = ceil(3/8) = 1 字节/索引

从 transcript 挤压 3 字节：假设 [0x05, 0x02, 0x07]
  index₀ = 5 mod 8 = 5
  index₁ = 2 mod 8 = 2
  index₂ = 7 mod 8 = 7

indices = [5, 2, 7]

generator g = 8 次单位根
points = [g⁵, g², g⁷]
```

#### 5.2 提取被挑战行

```
行 5: matrix[5*4 .. 5*4+4] = [14, 4, 10, 15]
行 2: matrix[2*4 .. 2*4+4] = [8, 2, 4, 11]
行 7: matrix[7*4 .. 7*4+4] = [5, 6, 3, 9]

submatrix = [14, 4, 10, 15, 8, 2, 4, 11, 5, 6, 3, 9]   // 3 行 × 4 列 = 12 个元素
```

#### 5.3 prover_hint + Merkle 打开

```cpp
prover_state.prover_hint(submatrix);
merkle_tree::open(prover_state, matrix_commit_mt, witness.matrix_witness, indices);
```

---

### 六、verify 阶段完整模拟

```
1. 挤压 indices = [5, 2, 7]
2. 接收 submatrix = [14, 4, 10, 15, 8, 2, 4, 11, 5, 6, 3, 9]
3. 重新计算叶子哈希:
   leaf₅ = H(encode([14, 4, 10, 15]))
   leaf₂ = H(encode([8, 2, 4, 11]))
   leaf₇ = H(encode([5, 6, 3, 9]))
4. 从 transcript 读取 Merkle 提示
5. 重建根，与 Commitment.root 比较 → ✓
```

---

### 七、最终结果

```
prover open 返回的 Evaluations<Source>:
  points = [g⁵, g², g⁷]
  matrix = [14,4,10,15, 8,2,4,11, 5,6,3,9]   （3 行 × 4 列）

verifier verify 返回的 Evaluations<Source>:
  points = [g⁵, g², g⁷]
  matrix = [14,4,10,15, 8,2,4,11, 5,6,3,9]

二者一致：✓
验证通过：✓
```

**matrix 每行的含义：**

```
行 i = [P₀₀(gⁱ), P₀₁(gⁱ), P₁₀(gⁱ), P₁₁(gⁱ)]
```

即第 `i` 个域点上，`v0` 的两个子块和 `v1` 的两个子块的求值结果。

---

### 多见证打开时的水平拼接

当 `open` 接收多个 witness 时（例如在 WHIR 的首轮 STIR 中打开多个初始承诺），输出矩阵会被水平拼接：

```cpp
std::size_t n_witnesses = witnesses_list.size();
std::size_t stride = n_witnesses * num_cols();
std::vector<Source> matrix(indices.size() * stride, Source::zero());

std::size_t col_offset = 0;
for (const auto* w : witnesses_list) {
    // 提取 w 的被挑战行，复制到 matrix 的 [col_offset, col_offset+num_cols) 列
    for (std::size_t pi = 0; pi < indices.size(); ++pi) {
        for (std::size_t c = 0; c < num_cols(); ++c)
            matrix[pi * stride + col_offset + c] = w->matrix[indices[pi] * num_cols() + c];
    }
    col_offset += num_cols();
}
```

**`stride = n_witnesses * num_cols()` 的含义：** 输出矩阵每行的总列数。如果有 2 个 witness，每个有 4 列，则 stride = 8，每行包含两个 witness 的被挑战行并排排列。

**`col_offset` 的作用：** 将不同 witness 的子矩阵放到输出矩阵的正确列偏移位置。第一个 witness 占列 [0, 4)，第二个占列 [4, 8)。

**verify 中的对应逻辑：**

```cpp
std::size_t col_offset = 0;
for (const auto* c : commitments_list) {
    // 接收 submatrix，验证 Merkle
    // 然后复制到输出矩阵的 [col_offset, col_offset+num_cols) 列
    for (std::size_t pi = 0; pi < indices.size(); ++pi) {
        for (std::size_t c2 = 0; c2 < num_cols(); ++c2)
            matrix[pi * stride + col_offset + c2] = submatrix[pi * num_cols() + c2];
    }
    col_offset += num_cols();
}
```

---

### 这个例子对应代码中的哪些函数

| 函数 | 作用 |
|------|------|
| `Config::from_params()` | 计算 codeword_length, num_cols 等 |
| `Config::commit()` | 编码 + Merkle + OOD |
| `interleaved_rs_encode()` | 切分 + 零填充 + NTT + 转置 |
| `Config::receive_commitment()` | 验证者接收承诺 |
| `Config::open()` | 多见证水平拼接打开 |
| `Config::verify()` | 多承诺验证 + 水平拼接 |
| `Config::num_cols()` | 返回 num_vectors × interleaving_depth |
| `Config::message_length()` | 返回 vector_size / interleaving_depth |

---

## 总结

### commit 证明了什么

`commit` 阶段证明者向验证者承诺了一组多项式的 RS 编码。具体来说：
- 通过 Merkle 树根哈希，证明者**绑定**到一个特定的编码矩阵（无法事后修改）
- 通过 OOD 求值（如果有），证明者提供了编码矩阵与原始多项式之间一致性的初步证据
- 验证者只需保存 O(1) 的根哈希，而非 O(codeword_length × num_cols) 的完整矩阵

### open 证明了什么

`open` 阶段证明者向验证者揭示了编码矩阵在特定行上的值。具体来说：
- 证明者发送被挑战行的原始数据（submatrix）
- 证明者发送 Merkle 路径（兄弟哈希），允许验证者从叶子重建根
- 这证明了：**这些行确实是承诺矩阵的一部分**

### verify 检查了什么

`verify` 阶段验证者执行以下检查：
1. **重新计算叶子哈希**：从接收到的 submatrix 重新计算 `commit_leaves`，确保数据未被篡改
2. **Merkle 路径验证**：从叶子哈希 + 兄弟提示重建根，与承诺的根比较
3. **一致性**：如果根匹配，则 submatrix 确实来自承诺的矩阵

如果证明者篡改了任何一行的任何一个字节，重新计算的叶子哈希将不同，Merkle 路径验证将失败。

### OOD 采样解决什么问题

OOD（Out-of-Domain）采样解决的是**近似码字检测**问题：

- 在列表解码模式下，可能存在多个码字都在距离界内
- 仅靠域内查询无法区分它们（因为查询的行可能恰好相同）
- OOD 采样在"域外"随机点处对原始多项式求值，提供了额外的一致性约束
- 如果证明者提交的不是合法码字，域外求值很可能不一致（因为不同的码字对应不同的隐含多项式）

**数学直觉：** 两个不同的度-(k-1) 多项式最多在 k-1 个点上相等。如果在 k 个以上的随机点上求值，它们几乎必然不同。OOD 采样利用了这个性质。

### 域内查询解决什么问题

域内查询解决的是**码字绑定**问题：

- 证明者已经通过 Merkle 树承诺了编码矩阵
- 域内查询随机选择矩阵的行，要求证明者揭示这些行的值
- 通过 Merkle 路径验证，确认这些行确实来自承诺的矩阵
- 如果证明者试图使用不同的码字，域内查询以高概率检测到不一致

**每个查询的安全性贡献：**
- 唯一解码：每查询 `-log₂((1+rate)/2)` 比特
- 列表解码：每查询 `-log₂(√rate + η)` 比特

### Merkle 树在协议中承担什么角色

Merkle 树在 IRS 承诺协议中承担**数据完整性证明**的角色：

1. **承诺阶段**：将编码矩阵的所有行哈希为叶子，构建树，发送根。根哈希是对整个矩阵的紧凑承诺。

2. **打开阶段**：对被挑战的行，生成从叶子到根的路径（兄弟哈希）。路径长度 = O(log(codeword_length))。

3. **验证阶段**：验证者从接收到的行数据重新计算叶子哈希，然后用兄弟提示重建根。如果根匹配，则行数据确实来自承诺的矩阵。

**关键优势：** 验证者不需要存储完整矩阵，只需存储根哈希（O(1) 空间）。打开和验证的时间复杂度为 O(log(codeword_length))，而非 O(codeword_length)。

### 为什么 IRS commit 是 WHIR 协议中的核心多项式承诺组件

IRS（Interleaved Reed-Solomon）承诺是 WHIR 协议的核心，因为：

1. **多项式表示**：WHIR 中的多项式系数向量通过 IRS 编码为码字，承诺到 Merkle 树中。这提供了信息论绑定（RS 码的唯一解码性）和密码学绑定（Merkle 树的碰撞抗性）。

2. **STIR 折叠支持**：WHIR 的 STIR 协议逐轮折叠向量，每轮需要：
   - 承诺折叠后的向量（`commit`）
   - 打开前一轮的域内行（`open`）
   - 验证这些行（`verify`）
   IRS 的高效打开（O(log n) Merkle 路径）使得 STIR 轮次的开销很小。

3. **交错优化**：通过 `interleaving_depth`，IRS 将大向量切分为小子块，降低单次 NTT 的规模，提高 GPU 并行效率。这对于 WHIR 中频繁的编码操作至关重要。

4. **安全性分析**：IRS 的安全性参数（`rbr_ood_sample`, `rbr_queries`, `rbr_soundness_fold_prox_gaps`）直接决定了 WHIR 协议的整体安全性。`Config::from_params()` 中的参数推导确保了在给定安全级别下的正确配置。

5. **灵活的解码模式**：唯一解码（`unique_decoding = true`）提供更简单的安全性分析，列表解码（`unique_decoding = false`）提供更低的码率（更强的纠错能力），WHIR 可以根据应用场景选择合适的模式。
