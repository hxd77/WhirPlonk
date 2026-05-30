# WHIR C++ 实现

本目录包含 WHIR PCS 协议的实验性 C++20 实现，旨在跟踪仓库中的 Rust 参考实现，并支持确定性的跨语言对比。

## 当前状态

已实现的组件：

- Goldilocks 域、Goldilocks 扩展域（ext2、ext3）、嵌入映射、多线性工具
- 交错 Reed-Solomon 编码和 NTT 辅助函数
- 矩阵承诺和 Merkle 树承诺
- 基于 SHAKE-128 的 Fiat-Shamir transcript，采用 WHIR 风格的域分隔
- 工作量证明（PoW）
- Sumcheck 协议
- WHIR `commit -> prove -> verify` 流程（用于 PCS）
- ZK WHIR 组件（零知识扩展）
- 可选的 OpenMP 多线程加速
- 可选的 CUDA GPU 加速（NTT、RS 编码、Merkle 哈希）
- Blake3 SIMD 加速（SSE4.1/AVX2/AVX512）
- 性能分析工具（CSV 输出、CUDA 跟踪）

当前限制：

- C++ 验证器尚未实现与任意 Rust 证明的字节级兼容。
- Rust 证明 → C++ 验证器 和 C++ 证明 → Rust 验证器 目前未被自动化测试覆盖。
- CLI 仅支持 `--type PCS`、`--sec ConjectureList` 和 `--fold_type ProverHelps`。
- C++ CLI 目前支持 `Blake3` 和 `Sha2`；Rust CLI 还支持 `Sha3` 和 `Keccak`。
- 本代码是学术原型，未经安全审计，不应用于生产环境。

## 构建

在项目根目录下执行（推荐）：

```bash
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build --config Release
```

或在 `cpp/` 目录下执行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

主可执行文件：

```bash
./cpp/build/whir_cli        # Linux/macOS
./cpp/build/Release/whir_cli.exe  # Windows MSVC
```

## CMake 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `WHIR_OPENMP` | `ON` | 启用 OpenMP 多线程加速 |
| `WHIR_CUDA` | `OFF` | 启用 CUDA GPU 加速 |
| `WHIR_CUDA_EXPERIMENTAL_NTT` | `ON` | CUDA 启用时，开启 NTT/RS 编码 GPU 路径 |
| `WHIR_BUILD_BENCHMARKS` | `ON` | 构建基准测试可执行文件 |
| `WHIR_BUILD_TESTS` | `ON` | 构建测试和 golden dump 生成器 |
| `WHIR_BLAKE3_SIMD` | `ON` | 启用 Blake3 SIMD（SSE4.1/AVX2） |
| `WHIR_BLAKE3_AVX512` | `OFF` | 启用 Blake3 AVX512 后端 |

示例：关闭 OpenMP 的单线程构建：

```bash
cmake -S cpp -B cpp/build -DWHIR_OPENMP=OFF
```

示例：关闭 Blake3 SIMD 的跨平台对拍构建：

```bash
cmake -S cpp -B cpp/build -DWHIR_BLAKE3_SIMD=OFF
```

## CUDA 构建

CUDA 支持是可选的，针对 NTT、RS 编码和 Merkle 哈希路径提供 GPU 加速。详见 [GPU_ACCELERATION.md](GPU_ACCELERATION.md)。

```bash
cmake -S cpp -B cpp/build_cuda -DWHIR_CUDA=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_CUDA_ARCHITECTURES=89
cmake --build cpp/build_cuda --config Release
```

请使用与你的 GPU 匹配的 CUDA 架构（`89` 对应 Ada Lovelace，`80` 对应 Ampere 等）。默认为 `75`（Turing+）。

## CLI 用法

```bash
./cpp/build/whir_cli [OPTIONS]
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-t, --type` | 协议类型 | `PCS` |
| `-l, --security-level` | 安全级别 | `128` |
| `-p, --pow-bits` | 工作量证明位数 | `20` |
| `-d, --num-variables` | 多变量数量 | `20` |
| `-e, --evaluations` | 求值点数量 | `1` |
| `-r, --rate` | 逆速率 | `1` |
| `--reps` | 验证者重复次数 | `1000` |
| `-k, --fold` | 折叠因子 | `4` |
| `--sec` | 健全性类型 | `ConjectureList` |
| `--fold_type` | 折叠优化方式 | `ProverHelps` |
| `-f, --field` | 域类型 | `Goldilocks3` |
| `--hash` | 哈希算法 | `Blake3` |

运行示例：

```bash
./cpp/build/whir_cli \
  --type PCS \
  --security-level 128 \
  --num-variables 20 \
  --evaluations 1 \
  --rate 1 \
  --reps 1000 \
  --fold 4 \
  --sec ConjectureList \
  --fold_type ProverHelps \
  --field Goldilocks3 \
  --hash Blake3
```

CLI 会输出派生配置、证明者耗时、证明大小、验证者耗时和平均哈希次数。

## 测试

使用默认 CMake 选项 `WHIR_BUILD_TESTS=ON` 构建测试，然后运行：

```bash
ctest --test-dir cpp/build --output-on-failure
```

### 测试分类

**Golden dump 生成器**（与 Rust `examples/dump_*.rs` 一一对应）：

| C++ 可执行文件 | Rust 对应 | 功能 |
|----------------|-----------|------|
| `dump_algebra_fields` | `dump_fields` | 域运算 |
| `dump_algebra_utils` | `dump_algebra` | 代数工具 |
| `dump_algebra_ntt` | `dump_ntt` | NTT 变换 |
| `dump_hash` | `dump_hash` | 哈希引擎 |
| `dump_merkle_tree` | `dump_merkle_tree` | Merkle 树 |
| `dump_pow` | `dump_pow` | 工作量证明 |
| `dump_matrix_commit` | `dump_matrix_commit` | 矩阵承诺 |
| `dump_irs_commit` | `dump_irs_commit` | IRS 承诺 |
| `dump_sumcheck` | `dump_sumcheck` | Sumcheck 协议 |
| `dump_transcript` | `dump_transcript` | Transcript |
| `dump_rng` | `dump_rng` | 确定性 RNG |
| `dump_challenge_indices` | `dump_challenge_indices` | 挑战索引 |
| `dump_whir` | `dump_whir` | WHIR 协议完整流程 |
| `dump_whir_zk` | `dump_whir_zk` | ZK WHIR 协议 |
| `dump_golden_algebra` | — | 旧版完整 dump（向后兼容） |

**GoogleTest 单元测试**：

| 可执行文件 | 覆盖范围 |
|-----------|----------|
| `test_protocols` | challenge_indices、matrix_commit、proof_of_work、merkle_tree |

**CUDA 测试**（仅 `WHIR_CUDA=ON` 时构建）：

| 可执行文件 | 覆盖范围 |
|-----------|----------|
| `test_cuda_ntt` | CUDA NTT 正确性 |
| `test_cuda_rs_encode` | CUDA RS 编码 |
| `test_cuda_merkle_sha256` | CUDA SHA-256 Merkle 树 |
| `test_cuda_merkle_path` | CUDA Merkle 路径 |
| `test_cuda_irs_commit` | CUDA IRS 承诺 |

## 基准测试

基准测试在 `WHIR_BUILD_BENCHMARKS=ON`（默认）时自动构建：

| 可执行文件 | 测试内容 |
|-----------|----------|
| `bench_ntt` | NTT 性能 |
| `bench_ntt_compare` | NTT CPU vs CUDA 对比 |
| `bench_rs_encode` | RS 编码性能 |
| `bench_rs_encode_compare` | RS 编码 CPU vs CUDA 对比 |
| `bench_merkle_sha256_compare` | SHA-256 Merkle 树对比 |
| `bench_merkle_path_compare` | Merkle 路径对比 |
| `bench_irs_cuda_compare` | IRS 承诺 CPU vs CUDA 对比 |

## 教学演示

| 文件 | 功能 |
|------|------|
| `demo/demo_irs_commit.cpp` | IRS 承诺协议分步演示 |
| `demo/demo_open_verify.cpp` | 打开与验证流程演示 |

## 跨语言对拍

Golden dump 输出保存在 `dump_output/` 目录下，与 Rust 端的输出进行字节级对比：

```bash
# 运行 Rust golden dump
cargo run --example dump_whir --manifest-path ../rust/Cargo.toml

# 运行 C++ golden dump
./cpp/build/dump_whir

# 对比输出
python scripts/compare_cross_language_dumps.py
```

完整跨语言 CLI 对拍：

```bash
cargo build --release --manifest-path ../rust/Cargo.toml
cmake --build cpp/build --config Release --target whir_cli
python scripts/compare_whir.py --rust-bin rust/target/release/main.exe --cpp-bin cpp/build/whir_cli.exe
```

## Rust 兼容性

目标是与 Rust 参考实现在相同 WHIR PCS 参数下保持兼容：

```bash
cargo run --release --manifest-path rust/Cargo.toml --
```

兼容性意味着：

- 相同的域分隔符（domain separator）
- 相同的 transcript 吸收/挤压顺序
- 相同的 Fiat-Shamir 挑战
- 相同的查询采样顺序
- 相同的 Merkle 根和打开证明
- 兼容的证明序列化
- 双向验证器互操作

当前实现已有组件级 golden dump，但在自动化跨语言证明测试通过之前，应视为"兼容性进行中"。

## Transcript 兼容性

C++ transcript 使用 SHAKE-128，镜像 Spongefish 风格的 prover 消息、verifier 消息、hints 和域分隔。重要的兼容性要点：

- 协议参数的 CBOR 编码必须与 Rust 的 `serde` + `ciborium` 完全一致。
- 域元素必须编码为规范的小端序基域字（base-field limbs）。
- Prover 消息会被吸收并序列化；hints 会被序列化但不会被吸收。
- 挑战的挤压必须遵循与 Rust 完全相同的类型和字节顺序。

消息顺序、域编码、向量长度编码或域分隔符字节的任何更改都会改变所有下游挑战。

## 证明兼容性

证明字节分为：

- `narg_string`：transcript 绑定的 prover 消息
- `hints`：带外数据，如 Merkle 路径和打开的矩阵行

在声明证明兼容性之前，需要添加以下测试：

- Rust 证明由 C++ 验证
- C++ 证明由 Rust 验证
- transcript 模式相等性
- 固定输入的序列化证明字节相等性
- 对格式错误和篡改证明的拒绝

## 安全警告

此 C++ 实现是学术原型，未经安全审计。它缺乏足够的负面测试、模糊测试和跨语言证明互操作性测试。请勿用于保护真实资产或生产系统。

## 目录结构

```text
cpp/
├── CMakeLists.txt              # 主构建配置
├── main.cpp                    # CLI 入口
├── README.md                   # 本文件
├── GPU_ACCELERATION.md         # CUDA 加速详细说明
│
├── include/whir/               # Header-only 实现主体
│   ├── algebra/                #   代数基础
│   │   ├── goldilocks*.hpp     #     Goldilocks 域及扩展域
│   │   ├── embedding.hpp       #     嵌入映射
│   │   ├── multilinear*.hpp    #     多线性扩展
│   │   ├── linear_form.hpp     #     线性形式
│   │   ├── sumcheck.hpp        #     Sumcheck
│   │   ├── utilities.hpp       #     代数工具
│   │   └── ntt/                #     NTT 实现
│   │       ├── cooley_tukey.hpp
│   │       ├── cooley_tukey_goldilocks.hpp
│   │       ├── matrix.hpp
│   │       ├── mod_ntt.hpp
│   │       ├── transpose.hpp
│   │       ├── utils.hpp
│   │       └── wavelet.hpp
│   ├── hash/                   #   哈希引擎
│   │   ├── blake3_engine.hpp
│   │   ├── sha2_engine.hpp
│   │   ├── hash_engine.hpp
│   │   ├── hash_counter.hpp
│   │   └── copy_engine.hpp
│   ├── protocols/              #   协议实现
│   │   ├── whir/               #     WHIR 协议
│   │   │   ├── whir.hpp
│   │   │   ├── whir_prover.hpp
│   │   │   └── whir_verifier.hpp
│   │   ├── whir_zk/            #     ZK WHIR
│   │   │   ├── whir_zk.hpp
│   │   │   ├── whir_zk_impl.hpp
│   │   │   └── whir_zk_utils.hpp
│   │   ├── irs_commit.hpp      #     IRS 承诺
│   │   ├── matrix_commit.hpp   #     矩阵承诺
│   │   ├── merkle_tree.hpp     #     Merkle 树
│   │   ├── sumcheck_protocol.hpp
│   │   ├── proof_of_work.hpp
│   │   ├── challenge_indices.hpp
│   │   └── geometric_challenge.hpp
│   ├── transcript/             #   Fiat-Shamir transcript
│   │   └── transcript.hpp
│   ├── parameters.hpp          #   协议参数
│   ├── canonical_config.hpp    #   规范化配置
│   ├── deterministic_rng.hpp   #   确定性 RNG
│   ├── engines.hpp             #   引擎注册
│   ├── bits.hpp                #   位操作
│   ├── profiling.hpp           #   性能分析工具（CSV 输出、CUDA 跟踪）
│   └── utils.hpp               #   通用工具
│
├── cuda/                       # CUDA GPU 加速
│   ├── cuda_ntt.cuh            #   设备端算术和核函数声明
│   ├── cuda_ntt.cu             #   核函数实现（基-2/基-4 NTT、twiddle、转置）
│   ├── cuda_ntt.hpp            #   主机端 API、RAII DeviceBuffer
│   └── cuda_integration.hpp    #   高层调度、内存池、计时
│
├── tests/                      # 测试和 golden dump 生成器
│   ├── CMakeLists.txt          #   测试构建配置
│   ├── dump_*.cpp              #   Golden dump 生成器（15 个）
│   ├── test_protocols.cpp      #   GoogleTest 单元测试
│   └── test_cuda_*.cpp         #   CUDA 测试（9 个，仅 CUDA 构建）
│
├── bench/                      # 基准测试
│   ├── bench_ntt.cpp           #   NTT 性能
│   ├── bench_ntt_compare.cpp   #   NTT CPU vs CUDA
│   ├── bench_rs_encode*.cpp    #   RS 编码性能及对比
│   ├── bench_rs_leaf_hash*.cpp #   叶哈希对比
│   ├── bench_merkle_*.cpp      #   Merkle 树对比
│   ├── bench_irs_cuda_compare.cpp
│   └── debug_cuda_ntt.cpp      #   CUDA NTT 调试
│
├── demo/                       # 教学演示
│   ├── demo_irs_commit.cpp     #   IRS 承诺分步演示
│   └── demo_open_verify.cpp    #   打开与验证演示
│
├── dump_output/                # Golden dump 输出目录
│   ├── field_ouput/            #   域运算输出
│   ├── hash_output/            #   哈希输出
│   ├── indices_output/         #   挑战索引输出
│   ├── matrix_commit_output/   #   矩阵承诺输出
│   ├── merkle_tree_output/     #   Merkle 树输出
│   ├── pow_output/             #   工作量证明输出
│   ├── sumcheck_output/        #   Sumcheck 输出
│   ├── transcript_output/      #   Transcript 输出
│   ├── utils_output/           #   代数工具输出
│   └── whir_output/            #   WHIR 协议输出
│
└── third_party/                # 第三方 C 依赖（vendored）
    ├── blake3/                 #   BLAKE3 哈希（含 SIMD 后端）
    ├── sha256/                 #   SHA-256（Brad Conte 实现）
    └── keccak/                 #   Keccak
```
