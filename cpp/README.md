# WHIR C++ 实现

本目录包含 WHIR PCS 协议的实验性 C++20 实现，旨在跟踪仓库中的 Rust 实现，并支持确定性的跨语言对比。

## 当前状态

已实现的组件：

- Goldilocks 域、Goldilocks 扩展域、嵌入映射、多线性工具
- 交错 Reed-Solomon 编码和 NTT 辅助函数
- 矩阵承诺和 Merkle 树承诺
- 基于 SHAKE-128 的 Fiat-Shamir transcript，采用 WHIR 风格的域分隔
- 工作量证明（PoW）钩子
- Sumcheck 协议
- WHIR `commit -> prove -> proof -> verify` 流程（用于 PCS）
- 实验性 ZK WHIR 组件和测试
- 可选的 OpenMP 加速
- 可选的 CUDA NTT/编码集成

当前限制：

- C++ 验证器尚未实现与任意 Rust 证明的字节级兼容。
- Rust 证明 → C++ 验证器 和 C++ 证明 → Rust 验证器 目前未被自动化测试覆盖。
- CLI 仅支持 `--type PCS`、`--sec ConjectureList` 和 `--fold_type ProverHelps`。
- C++ CLI 目前支持 `Blake3` 和 `Sha2`；Rust CLI 还支持 `Sha3` 和 `Keccak`。
- 证明序列化和 transcript 模式的兼容性需要通过 golden 测试后，才能认为与 Rust 实现协议兼容。
- 本代码不应用于生产环境的密码学场景。

## 构建

在本目录下执行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

主可执行文件为：

```bash
./build/whir_cli
```

在 Windows 上使用 MinGW 或其他生成器时，请使用对应构建目录生成的可执行文件路径，例如 `build_mingw/whir_cli.exe`。

## CUDA 构建

CUDA 支持是可选的，目前针对部分 NTT 和编码路径提供 GPU 加速。

```bash
cmake -S . -B build_cuda -DWHIR_CUDA=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_CUDA_ARCHITECTURES=89
cmake --build build_cuda --config Release
```

请使用与你的 GPU 匹配的 CUDA 架构。

## 测试

使用默认 CMake 选项 `WHIR_BUILD_TESTS=ON` 构建测试，然后运行：

```bash
ctest --test-dir build --output-on-failure
```

`tests/` 目录还包含用于与 Rust examples 进行 golden 输出对比的 dumper，涵盖 transcript、Merkle、矩阵承诺、sumcheck、challenge-index 和 WHIR 等模块。

## 基准测试 / CLI

PCS 运行示例：

```bash
./build/whir_cli \
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

## Rust 兼容性

目标是与以下命令在相同 WHIR PCS 参数下保持兼容：

```bash
cargo run --release --
```

兼容性意味着：

- 相同的域分隔符（domain separator）
- 相同的 transcript 吸收/挤压顺序
- 相同的 Fiat-Shamir 挑战
- 相同的查询采样顺序
- 相同的 Merkle 根和打开证明
- 兼容的证明序列化
- 双向验证器互操作

当前实现已有部分组件级 golden dump，但在自动化跨语言证明测试通过之前，应视为"兼容性进行中"。

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

此 C++ 实现是实验性的。它尚未经过审计，目前缺乏足够的负面测试、模糊测试和跨语言证明互操作性测试。请勿用于保护真实资产或生产系统。

## 仓库目录结构

```text
cpp/
  CMakeLists.txt        # 主构建配置
  main.cpp              # CLI 入口
  include/whir/         # Header-only 实现主体
    algebra/            # 代数基础（域、NTT、多项式）
    hash/               # 哈希引擎（Blake3、SHA2）
    protocols/          # 协议实现（WHIR、sumcheck、Merkle）
    transcript/         # Fiat-Shamir transcript
  cuda/                 # CUDA 加速实现
  demo/                 # 教学演示
  tests/                # 测试和 golden dump 生成器
  third_party/          # 第三方依赖（Blake3、SHA-256、Keccak）
  bench/                # 基准测试
```
