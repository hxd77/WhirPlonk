# AGENT.md

本文件给代码代理和自动化助手使用，目标是在本仓库内修改代码时更快进入状态，并降低误改协议实现或生成产物的风险。写代码时记得加上合适的注释。用中文。更改文件时不要删除我的代码注释。

## 项目概览

WhirPlonk 基于 WHIR 协议原型，Rust 代码是主要参考实现，C++ 目录是对 Rust 行为的移植、演示、性能实验和跨语言 golden 对拍。

重要提醒：README 已声明该实现是学术原型，未经过充分安全审计，不应被当作生产级密码学库使用。涉及协议、安全参数、Fiat-Shamir transcript、Merkle/hash、field arithmetic、NTT、sumcheck 等逻辑时，要保守修改，并优先补充或运行对拍测试。

## 目录速览

- `src/`: Rust 主实现。
  - `src/algebra/`: 域、扩域、多线性、多项式/线性形式、NTT 等代数基础。
  - `src/hash/`: BLAKE3、digest/copy/hash counter 等哈希引擎。
  - `src/transcript/`: transcript 编码和 sponge 适配。
  - `src/protocols/`: WHIR、ZK WHIR、sumcheck、Merkle tree、matrix/IRS commit、PoW、challenge indices 等协议模块。
  - `src/bin/`: CLI 和 benchmark 入口。
- `examples/dump_*.rs`: Rust golden 输出生成器，常与 C++ dumper 一一对应。
- `benches/`: Rust benchmark。
- `cpp/`: C++ 移植和测试。
  - `cpp/include/whir/`: header-only C++ 实现主体。
  - `cpp/main.cpp`: C++ CLI 入口。
  - `cpp/tests/`: C++ dumper、demo、GoogleTest 单测。
  - `cpp/dump_output/`: Rust/C++ golden 输出对拍材料。
  - `cpp/third_party/`: vendored BLAKE3、SHA-256、Keccak。
  - `cpp/cuda/`: 可选 CUDA 加速路径。
- `scripts/compare_whir.py`: Rust CLI 与 C++ CLI 的跨语言一致性脚本。

## 常用命令

Rust:

```powershell
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test --all-targets
cargo build --release
cargo run --release -- --help
```

C++:

```powershell
cmake -S cpp -B cpp/build -DWHIR_BUILD_TESTS=ON
cmake --build cpp/build --config Release
ctest --test-dir cpp/build --output-on-failure
```

可选 C++ 配置:

```powershell
cmake -S cpp -B cpp/build -DWHIR_OPENMP=OFF
cmake -S cpp -B cpp/build -DWHIR_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=89
cmake -S cpp -B cpp/build -DWHIR_BLAKE3_SIMD=OFF
```

跨语言 CLI 对拍:

```powershell
cargo build --release
cmake --build cpp/build --config Release --target whir_cli
python scripts/compare_whir.py --rust-bin target/release/main.exe --cpp-bin cpp/build/whir_cli.exe
```

在非 Windows 环境中去掉 `.exe` 后缀即可。`scripts/compare_whir.py` 当前会从脚本目录推导项目根目录；如果发现二进制路径查找异常，优先显式传入 `--rust-bin` 和 `--cpp-bin`。

## 代码风格

- Rust edition 是 2021，最低 Rust 版本见 `Cargo.toml` 的 `rust-version`。
- Rust 格式化遵循 `rustfmt.toml`：
  - `reorder_imports = true`
  - `imports_granularity = "Crate"`
  - `group_imports = "StdExternalCrate"`
- Rust clippy 在 `Cargo.toml` 中启用了 `all`、`nursery`、`pedantic` 的 warn 级别，并显式放宽部分 pedantic lint。新增代码应尽量保持 clippy 干净。
- C++ 使用 C++20，C 使用 C11。CMake 中默认开启 Release build type、OpenMP、BLAKE3 SIMD，CUDA 默认关闭。
- C++ 头文件实现应尽量保持与 Rust 语义一致；不要为了局部性能微调改变 transcript 顺序、序列化格式、随机挑战派生或 proof 布局。

## 修改协议代码时的约束

- Rust 是参考实现。修改 C++ 时，先找到对应的 Rust 文件和 `examples/dump_*.rs`；修改 Rust 时，同步评估 C++ port 是否需要更新。
- 对 field arithmetic、extension fields、NTT、hash/transcript、challenge sampling、PoW、Merkle path、commit/open/verify 流程的改动都属于高风险改动。
- 避免引入非确定性输出。golden/dumper 依赖稳定输出进行跨语言比对。
- 不要随意改变公开 CLI 参数、默认参数、安全参数计算或输出格式；如果确实需要，更新 README、脚本和 C++ 对应逻辑。
- 对性能优化，先保留可读、可验证的参考路径，再增加优化分支。SIMD/OpenMP/CUDA 路径必须能回退到可对拍的 CPU 路径。

## 测试与验证建议

按改动范围选择验证强度：

- 只改 Rust 局部纯函数：运行 `cargo test --all-targets`，必要时加目标模块测试。
- 改 Rust 格式、lint 或 API：运行 `cargo fmt --all` 和 `cargo clippy --all-targets --all-features`。
- 改 C++ header/CLI/tests：重新配置/构建 CMake，并运行 `ctest --test-dir cpp/build --output-on-failure`。
- 改 Rust/C++ 共有协议语义：同时运行 Rust 测试、C++ 测试、相关 dumper/golden 对拍和 `scripts/compare_whir.py`。
- 改 hash、transcript、serialization 或 proof layout：优先检查 golden 输出是否需要有意更新；不要把差异当作普通快照刷新直接接受。

## 生成产物与仓库卫生

- 不要提交 `target/`、CMake build 目录、临时输出、profiling 文件或大体积本地构建产物。
- `.gitignore` 已忽略 `target/`、`outputs/`、`scripts/temp/`、`cpp/build/`、`cpp/tests/build/`、临时 golden diff 等路径。现有 `cpp/build_mingw*` 目录可能是本地构建残留，除非任务明确要求，不要改动或清理。
- 仓库中可能已有用户未提交修改。开始编辑前查看 `git status --short`，只修改任务相关文件，不要回滚用户改动。
- `cpp/third_party/` 是 vendored 依赖，除非正在修复第三方适配或构建问题，否则不要改动。

## 文档与输出

- 面向用户的说明可以使用中文；面向公开 API、代码注释和错误信息时，跟随周围文件的语言风格。
- README 的 CLI 帮助和选项说明应与 `src/bin/main.rs` 保持一致。
- 如果新增 dumper 或 golden 输出，尽量保持 Rust `examples/dump_*.rs` 与 C++ `cpp/tests/dump_*.cpp` 命名和内容结构对应。

