# WHIR C++ CUDA 加速说明

## 总体方案

本代码库中最适合 GPU 加速的首个目标是 Goldilocks Reed-Solomon 编码：

1. 对多项式分块进行零填充
2. 批量执行前向 NTT
3. 将结果转置为 Merkle 叶行顺序

这条路径在证明端工作中占主导地位，因为它具有规则性、大规模、纯整数运算的特点，并且易于与现有 CPU 实现进行精确验证。CPU 实现仍然是基线，CUDA 路径通过 CMake 可选启用。

## CPU 热点

适合 GPU 加速的候选：

- `include/whir/algebra/ntt/cooley_tukey.hpp`
  - `NttEngine::ntt_batch`
  - `apply_twiddles`
  - `transpose`
- `include/whir/algebra/ntt/mod_ntt.hpp`
  - `ark_ntt` / `interleaved_rs_encode`
- `include/whir/protocols/matrix_commit.hpp`
  - 哈希前行编码，当数据已在大型平坦缓冲区中时

任务特征：

- 数据并行
- 有限域向量/矩阵计算
- NTT/多项式求值
- 转置密集型内存移动
- 哈希/Merkle 相邻，但哈希本身应作为单独后端处理

不太适合作为首批目标：

- 转录器和验证器逻辑：分支多、规模小、延迟主导
- Merkle 路径验证：每次启动的工作量太少
- 小于约 64K 有限域元素的小型 NTT：启动和拷贝开销可能超过计算节省
- sumcheck 控制流：后续有用，但需先隔离大型折叠/归约核函数

## CUDA 实现

文件：

- `cuda/cuda_ntt.cuh`：设备端 Goldilocks 算术和核函数声明
- `cuda/cuda_ntt.cu`：基-2/基-4 核函数、twiddle 核函数、分块转置、启动包装器
- `cuda/cuda_ntt.hpp`：主机端 API、`CUDA_CHECK`、RAII `DeviceBuffer`
- `cuda/cuda_integration.hpp`：高层调度、内存池、计时、运行时开关

GPU 内存池：

- 静态 `GpuPool` 单例管理设备内存，避免反复 `cudaMalloc`/`cudaFree`
- 提供 `data()`、`temp()`、`input()`、`bytes()` 等方法获取预分配缓冲区
- `roots()` 缓存预计算的 twiddle 因子
- `reset_alloc_timing()` 和 `last_alloc_ms()` 用于监控内存分配开销

性能分析工具：

- `include/whir/profiling.hpp`：提供 CSV 性能输出和 CUDA 跟踪功能
- 环境变量 `WHIR_PROFILE=1` 启用 CSV 格式的性能数据输出到 stderr
- 环境变量 `WHIR_CUDA_TRACE=1` 启用 CUDA 操作的详细跟踪
- `ScopedTimer` RAII 类自动记录代码块执行时间
- `record()` 函数手动记录性能数据点

核函数映射：

- 基-2 NTT：一个线程处理一对蝶形运算 `(a, b) -> (a + b*w, a - b*w)`
- 基-4 NTT：一个线程在寄存器中处理一个 4 点块
- twiddle：一个线程处理一个矩阵元素 `data[i][j] *= roots[i*j*step]`
- 转置：一个线程在异地转置缓冲区中处理一个矩阵元素

当前调度将每个递归 6 步层跨所有独立 NTT 块进行批量处理。这避免了为每个子块启动整个递归流程（这对大型 NTT 是致命的）。每一层现在执行批量转置、批量 twiddle 和批量子 NTT 调用。

递归调度使用 `data/scratch` 双缓冲 ping-pong。转置直接写到另一块设备缓冲区，子 NTT 在该缓冲区继续执行，从而避免每次转置后额外的 `cudaMemcpyDeviceToDevice`。

RS encode GPU 快路径只上传紧凑系数数组。device 端先 `cudaMemset` 清零输出 codeword，再由 `pack_rs_coeffs_kernel` 将每个多项式分块 scatter 到 NTT 输入布局，随后执行批量 NTT 和最终转置。这避免了在 CPU 上构造完整零填充 codeword 并上传。

另有 `RS encode -> Goldilocks LE bytes` 的融合路径，用于连接 matrix commit 的 leaf hashing：device 端在最终转置后直接调用字节编码 kernel，host 端收到的就是逐行小端字节缓冲区。这避免了 CPU 再扫描一遍矩阵执行 `encode_into<Goldilocks>`。

`RS encode -> SHA-256 leaf hashes` 路径进一步把 leaf hash 留在 GPU 上，最终只回传 `codeword_length * 32` 字节 hash。当前实现对 `codeword_length <= 65536` 使用 direct Goldilocks-row SHA kernel：每个线程负责一个 leaf message，直接从转置后的 Goldilocks 行读取元素、按 little-endian 展开并执行 SHA-256 padding/压缩。更大规模先走已验证的 GPU `encode_to_bytes`，再在 GPU 上做 SHA-256，以保证所有规模与 CPU `Sha2::hash_many` 完全一致。

`SHA-256 Merkle tree` 路径从 32B leaves 出发，在 GPU 端补齐零 hash，并逐层调用固定 64B 消息的 SHA-256 kernel 构建父节点。接口支持两种回传模式：root-only 只拷回 32B 根，适合单纯承诺；full-witness 拷回完整 nodes，适合后续生成 Merkle open path。

`RS encode -> SHA-256 leaves -> SHA-256 Merkle root` 端到端路径把叶子哈希和 Merkle 内部节点都保留在 GPU 上，最后只回传 32B root。该路径避免了 leaf hashes 的 D2H/H2D 往返，适合作为 prover commit 阶段的 root-only 快路径；如果后续要生成 open path，仍需要 full-witness 或按查询索引回传路径节点。

`SHA-256 Merkle open path` 路径在 GPU 端构建完整树，但 host 端只计算需要回传的 sibling node indices，再由 gather kernel 把这些 32B 节点打包回传。hint 顺序与 CPU `open_path` 完全一致，支持重复查询索引的排序/去重/兄弟合并规则。

IRS commit/open 已接入 SHA-256 CUDA fast path：在 `matrix_commit_mt` 使用 SHA-256 且运行时 CUDA dispatch 开启时，`commit()` 会保存 leaf hashes、使用 GPU Merkle root-only 发送承诺，并避免保存完整 Merkle witness；`open()` 会用保存的 leaves 和挑战 indices 走 GPU Merkle path gather，只回传需要的 sibling hints。BLAKE3、非 CUDA、或不满足条件的路径仍保留 CPU full-witness 行为。

内存和分歧说明：

- 转置目前优先考虑正确性和 T400 实测性能，而非共享内存分块
- 已提交的转置实现是基于全局内存的异地转置核函数；标准 32x8 shared-memory tiled 版本也已验证正确，但在 T400 上更慢
- 基-2 加载和存储对连续小块基本是合并的
- twiddle 跳过第 0 行和第 0 列，仅在矩阵边界产生轻微分支分歧
- 当前集成使用可复用设备内存池，避免重复 `cudaMalloc`
- 尚未使用锁页主机内存；如果端到端 H2D/D2H 时间在基准测试中占主导，可添加
- 不建议使用统一内存，因为需要精确计时且访问模式可预测

## 正确性

整数有限域结果必须精确匹配。CUDA 测试强制将相同输入通过：

- CPU 基线：`whir::cuda::set_gpu_dispatch_enabled(false)`
- GPU 路径：`whir::cuda::set_gpu_dispatch_enabled(true)` 且阈值设为 `0`

GoogleTest 文件 `tests/test_cuda_ntt.cpp` 覆盖：

- 随机输入
- 多批次
- 低于和高于一个 CUDA 块工作量的规模
- 特殊值：`0`、`1`、`p-1`、`p-2`、`2^32-1`、`2^32`、约简后的 `UINT64_MAX`

对于后续添加的浮点核函数，记录：

- 最大绝对误差
- 最大相对误差
- 平均绝对误差
- 首次不匹配的失败索引和输入值

## 基准测试

`bench/bench_ntt_compare.cpp` 输出：

- 输入规模
- CPU 总耗时
- GPU H2D 耗时
- GPU 核函数耗时
- GPU D2H 耗时
- GPU 总耗时
- 仅核函数加速比
- 端到端加速比
- 正确性结果

## 编译指令

### 环境要求

- CUDA Toolkit >= 11.0
- GPU 架构 >= sm_75 (Turing 及以上)
- CMake >= 3.16

### Linux

```bash
cmake -S cpp -B cpp/build_cuda -DUSE_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=89 -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build_cuda --config Release
```

### Windows (NMake)

如果 Visual Studio 生成器找不到 CUDA MSBuild 工具集，使用 VS 开发者环境加 NMake：

```bat
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64

cmake -S cpp -B cpp\build_cuda -G "NMake Makefiles" `
  -DUSE_CUDA=ON `
  -DCMAKE_CUDA_ARCHITECTURES=75 `
  -DCMAKE_CUDA_COMPILER="C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.6\bin\nvcc.exe" `
  -DCMAKE_CUDA_FLAGS="-allow-unsupported-compiler" `
  -DCMAKE_BUILD_TYPE=Release

cmake --build cpp\build_cuda --config Release
```

### 当前环境编译指令（CUDA 12.6 + NVIDIA T400 4GB, sm_75）

**配置：**
```powershell
cmake -S cpp -B cpp/build_cuda -G "NMake Makefiles" -DUSE_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=75 -DCMAKE_BUILD_TYPE=Release
```

**编译全部目标：**

```powershell
cmake --build cpp/build_cuda --config Release
```

**仅编译 benchmark 和测试：**
```powershell
cmake --build cpp/build_cuda --config Release --target bench_ntt_compare bench_rs_encode_compare bench_merkle_sha256_compare bench_merkle_path_compare bench_irs_cuda_compare test_cuda_ntt test_cuda_rs_encode test_cuda_merkle_sha256 test_cuda_merkle_path test_cuda_irs_commit test_protocols
```

**运行 CUDA 测试：**
```powershell
ctest --test-dir cpp/build_cuda -R CudaNtt --output-on-failure
ctest --test-dir cpp/build_cuda -R CudaRsEncode --output-on-failure
ctest --test-dir cpp/build_cuda -R CudaMerkleSha256 --output-on-failure
ctest --test-dir cpp/build_cuda -R CudaMerklePath --output-on-failure
ctest --test-dir cpp/build_cuda -R CudaIrsCommit --output-on-failure
cpp/build_cuda/tests/test_protocols.exe
```

**运行 benchmark：**

```powershell
cpp/build_cuda/bench_ntt_compare.exe --sizes 1024 4096 65536 1048576 16777216 --runs 3
cpp/build_cuda/bench_rs_encode_compare.exe --runs 3 --warmups 1
cpp/build_cuda/bench_merkle_sha256_compare.exe --runs 3 --warmups 1
cpp/build_cuda/bench_merkle_path_compare.exe --runs 3 --warmups 1 --queries 32
cpp/build_cuda/bench_irs_cuda_compare.exe --runs 3 --warmups 1
```

如果 NMake 找不到 nvcc，显式指定编译器路径：
```powershell
-DCMAKE_CUDA_COMPILER="C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.6\bin\nvcc.exe" -DCMAKE_CUDA_FLAGS="-allow-unsupported-compiler"
```

### 纯 CPU 构建（不启用 CUDA）

```bash
cmake -S cpp -B cpp/build_cpu -DUSE_CUDA=OFF
cmake --build cpp/build_cpu --config Release
```

### 仅运行 CPU 构建的测试

```bash
cmake --build cpp/build_cpu && ctest --test-dir cpp/build_cpu --output-on-failure
```

## 结果解读

- 小规模时，CPU 通常更快，因为启动和 PCIe 拷贝占主导
- 大规模批量 NTT 时，仅核函数加速比会先显现
- 端到端加速需要每字节拷贝有足够的算术运算，或让数据在 GPU 上驻留跨 RS 编码、折叠、哈希和 Merkle 构建
- 在 NVIDIA T400 等小型工作站 GPU 上，当前优先保证正确性的递归 GPU NTT 可能比优化的 CPU 路径慢得多，直到分阶段 NTT 核函数和分块转置被融合/优化
- RS encode 的 `gpu_wall_ms` 包含 CPU 侧零填充、GPU NTT、最终转置和回拷；`gpu_total_ms` 只包含 CUDA event 统计到的 H2D/kernel/D2H

### NVIDIA T400 4GB 实测数据（CUDA 12.6, sm_75, Release 构建，批量递归 + ping-pong 调度后）

```text
输入规模     CPU 耗时(ms)   GPU 核函数(ms)  GPU 总耗时(ms)  正确性
2^10         0.0744         0.6815          0.7494          通过
2^12         1.5518         0.3298          0.3868          通过
2^16         7.4314         1.9392          2.1624          通过
2^20         182.6688       40.4944         42.2678         通过
2^24         2825.7168      553.3938        577.3929        通过
```

对照实验：32x8 shared-memory tiled transpose 在同一 T400 上正确性通过，但性能更差：

```text
输入规模     GPU 总耗时(ms)
2^20         233.8622
2^24         2456.7957
```

### RS encode 端到端实测（CUDA 12.6, sm_75, Release, GPU 端零填充/打包, `--runs 3 --warmups 1`）

```text
poly_size  codeword_length  depth  polys  CPU ms    GPU H2D ms  GPU wall ms  end-to-end speedup  correctness
2^12       2^14             4      4      4.2922    0.0453      7.4766       0.574               PASS
2^14       2^16             4      4      18.1397   0.1287      28.1230      0.645               PASS
2^16       2^18             4      4      100.9222  0.3062      84.7164      1.191               PASS
2^18       2^20             4      4      502.1479  0.7801      403.3382     1.245               PASS
```

相比上传完整零填充 codeword，最大 case 的 H2D 从约 `11 ms` 降至约 `0.8 ms`。端到端收益较温和，因为当前主要时间转移到了 GPU NTT/final transpose 和 D2H。

### RS encode 到 leaf bytes 实测（CUDA 12.6, sm_75, Release, `--runs 3 --warmups 1`）

```text
poly_size  codeword_length  depth  polys  CPU ms    GPU wall ms  end-to-end speedup  correctness
2^12       2^14             4      4      5.3429    3.6329       1.471               PASS
2^14       2^16             4      4      21.8933   13.9432      1.570               PASS
2^16       2^18             4      4      115.1740  76.2152      1.511               PASS
2^18       2^20             4      4      571.6963  404.2058     1.414               PASS
```

这个 benchmark 对比的是 `CPU RS encode + CPU encode_into<Goldilocks>` 与 `GPU RS encode + GPU LE byte encode`，输出可直接作为 CPU hash_many 的输入。

### RS encode 到 BLAKE3 leaf hash 半融合实测（CUDA 12.6, sm_75, Release）

```text
poly_size  codeword_length  depth  polys  message_size  CPU ms    GPU bytes ms  CPU hash ms  GPU+hash wall ms  speedup  correctness
2^12       2^14             4      4      128           5.6988    7.6599        0.2028       7.8845            0.723    PASS
2^14       2^16             4      4      128           23.5255   23.6512       0.5361       24.6719           0.954    PASS
2^16       2^18             4      4      128           119.6112  84.9083       1.2500       88.2017           1.356    PASS
2^18       2^20             4      4      128           581.6998  409.2373      6.9414       422.6668          1.376    PASS
```

在默认 `num_polys=4, depth=4` 时每行 128 字节，BLAKE3 CPU SIMD hash 很快，因此当前瓶颈仍主要是 GPU 侧 RS/bytes 和 D2H。完整 GPU hash/Merkle 只有在能同时省掉 leaf bytes D2H 或后续 Merkle 层也留在 GPU 上时才会更有意义。

### RS encode 到 SHA-256 leaf hash 全融合实测（CUDA 12.6, sm_75, Release）

```text
poly_size  codeword_length  depth  polys  message_size  CPU ms     GPU kernel ms  GPU D2H ms  GPU wall ms  kernel speedup  end-to-end speedup  correctness
2^12       2^14             4      4      128           24.7425    5.3908         0.1704      5.8979       4.590           4.195                PASS
2^14       2^16             4      4      128           87.9132    22.5361        0.3323      23.6775      3.901           3.713                PASS
2^16       2^18             4      4      128           315.4324   70.3767        0.8254      73.7709      4.482           4.276                PASS
2^18       2^20             4      4      128           1831.6170  390.3831       4.8031      406.9854     4.692           4.500                PASS
```

这个路径对比的是 `CPU RS encode + CPU Sha2 leaf hash` 与 `GPU RS encode + GPU SHA-256 leaf hash + 32B hashes D2H`。相较于半融合路径，它避免回传完整 leaf bytes；小/中规模还避免 materialize leaf bytes，大规模则优先选择已验证的 GPU bytes 中间路径来保持严格正确性。

### SHA-256 Merkle tree 实测（CUDA 12.6, sm_75, Release）

```text
leaves  nodes    CPU ms    GPU root wall ms  GPU witness wall ms  root speedup  witness speedup  correctness
2^10    2047     0.4246    0.4807            0.4652               0.883         0.913            PASS
2^12    8191     1.7680    0.7459            0.7771               2.370         2.275            PASS
2^16    131071   30.4047   4.2008            4.4912               7.238         6.770            PASS
2^20    2097151  509.8212  38.0731           44.7047              13.391        11.404           PASS
```

小树受 kernel launch 和 H2D/D2H 固定开销影响，GPU 不一定更快；从几千 leaves 开始，父层 hash 的批量并行度足够，root-only 和 full-witness 都有明显收益。full-witness 要回传约 `2 * leaf_layer_size - 1` 个 32B 节点，因此比 root-only 更受 PCIe 带宽影响。

### SHA-256 Merkle open path 实测（CUDA 12.6, sm_75, Release）

```text
leaves  queries  hints  CPU ms    GPU kernel ms  GPU D2H ms  GPU wall ms  end-to-end speedup  correctness
2^10    32       135    0.4563    0.3811         0.0354      0.4631       0.985               PASS
2^12    32       188    1.8264    0.6697         0.0532      0.7888       2.315               PASS
2^16    32       336    29.4395   3.8852         0.0435      4.3734       6.731               PASS
2^20    32       453    508.6519  48.3061        0.0665      51.6618      9.846               PASS
```

这个 benchmark 对比 `CPU build_tree + CPU open_path` 与 `GPU build_tree + GPU gather path hints`。与 full-witness 回传相比，D2H 只包含 root 和几百个 sibling hashes；查询数较小时，PCIe 拷贝基本不再是瓶颈。

### RS encode 到 SHA-256 Merkle root 端到端实测（CUDA 12.6, sm_75, Release）

```text
poly_size  codeword_length  depth  polys  CPU ms     GPU kernel ms  GPU D2H ms  GPU wall ms  kernel speedup  end-to-end speedup  correctness
2^12       2^14             4      4      33.3174    7.2519         0.0474      7.5049       4.594           4.439                PASS
2^14       2^16             4      4      128.5588   31.0000        0.0436      31.3390      4.147           4.102                PASS
2^16       2^18             4      4      475.5208   95.3615        0.0473      96.3762      4.987           4.934                PASS
2^18       2^20             4      4      3341.0706  537.5961       0.1083      541.5590     6.215           6.169                PASS
```

这个 benchmark 对比的是 `CPU RS encode + CPU Sha2 leaves + CPU Sha2 Merkle tree` 与 `GPU RS encode + GPU Sha2 leaves + GPU Sha2 Merkle root + 32B root D2H`。由于只回传 root，D2H 时间基本消失，收益主要取决于 GPU 侧 RS/leaf/Merkle kernel 总时间。

## CMake 集成

CUDA 是可选的：

```bash
cmake -S cpp -B cpp/build_cpu -DUSE_CUDA=OFF
cmake -S cpp -B cpp/build_cuda -DUSE_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=89
```

项目定义的宏：

- `USE_CUDA`：面向用户的别名
- `WHIR_CUDA`：内部 CUDA 构建开关
- `WHIR_CUDA_EXPERIMENTAL_NTT`：启用 Goldilocks NTT 调度

如果未启用 CUDA，头文件正常编译，使用 CPU 实现。如果启用了 CUDA 但通过 `WHIR_CUDA_DISABLE=1` 禁用运行时调度，同样使用 CPU 实现。

### 性能分析配置

环境变量控制性能数据收集：

```bash
# 启用 CSV 性能输出（输出到 stderr）
WHIR_PROFILE=1 ./cpp/build/whir_cli --num-variables 20

# 启用 CUDA 操作跟踪
WHIR_CUDA_TRACE=1 ./cpp/build_cuda/whir_cli --num-variables 20

# 同时启用两者
WHIR_PROFILE=1 WHIR_CUDA_TRACE=1 ./cpp/build_cuda/whir_cli
```

CSV 输出格式：
```text
mode,size,stage,time_ms
ntt,1048576,gpu_kernel,12.345678
rs_encode,1048576,gpu_total,45.678901
```

### IRS 集成状态

- SHA-256 matrix commit: `commit()` 使用 GPU Merkle root-only，`open()` 使用 GPU path gather。
- Witness: SHA-256/CUDA fast path 下 `matrix_witness.nodes` 可以为空，`matrix_leaves` 用于后续打开。
- 回退: BLAKE3、禁用 CUDA、或无 CUDA 构建仍使用 CPU `merkle_tree::commit/open` 和完整 witness。
- MSVC/CUDA 构建: 已修复 `transcript.hpp` 中 `__uint128_t` 依赖和 `sumcheck.hpp` OpenMP 无符号索引问题。

### IRS commit/open/verify 端到端实测（CUDA 12.6, sm_75, Release）

```text
vector_size  codeword_length  depth  vectors  CPU commit  CPU open  CPU verify  CPU total  GPU commit  GPU open  GPU verify  GPU total  speedup  correctness
2^8          2^10             4      4        4.0167      0.0206    0.3044      4.3417     154.1776    0.3238    0.0825      154.5839   0.028    PASS
2^10         2^12             4      4        10.6629     0.0239    0.1129      10.7997    7.0112      0.5632    0.2409      7.8153     1.382    PASS
2^12         2^14             4      4        41.6047     0.0358    0.1053      41.7458    25.8381     0.9267    0.1369      26.9017    1.552    PASS
2^14         2^16             4      4        159.8422    0.0838    10.7344     170.6604   109.4378    3.9432    0.3709      113.7519   1.500    PASS
2^16         2^18             4      4        564.8160    0.0462    0.1901      565.0523   664.1988    4.8981    0.2021      669.2990   0.844    PASS
```

该 benchmark 跑完整 `commit -> open -> receive_commitment -> verify`。当前收益主要来自 `commit` 阶段的 RS/leaf/Merkle GPU 路径；`open` 阶段为了按需生成 path 仍会在 GPU 端构树并 gather hints，因此在小/中规模下比 CPU open 更慢。`2^18` codeword 已纳入正式正确性覆盖；在当前 T400 上该规模端到端略慢于 CPU，主要受大规模 RS/bytes fallback 和 GPU path 构树成本影响。

### 推荐目录结构

```text
cpp/
  include/whir/          公共 CPU 头文件和可选调度点
  cuda/                  CUDA 核函数、主机端包装器、内存池
  tests/                 GoogleTest 正确性测试
  bench/                 CPU/GPU 微基准测试
  demo/                  协议演示
  third_party/           第三方哈希库
```

## 后续优化方向

- 让 RS 编码输出在 GPU 上驻留，直接传递给 GPU 折叠核函数
- 继续定位 direct SHA kernel 在 `codeword_length > 65536` 时的大偏移读取失配，验证后取消当前安全门控
- 为 BLAKE3 增加设备端实现，覆盖当前默认 matrix commit 哈希
- 用融合分阶段核函数替换每次子变换的核函数启动（针对大型 2 的幂次 NTT）
- 当传输时间明显时使用锁页主机缓冲区或异步拷贝
- 增加 WHIR 层端到端 benchmark，继续向上拆分 prover/verify 阶段耗时
- 添加 sumcheck 折叠核函数，作为精确 Goldilocks 向量运算，具有确定性归约顺序
- 添加 Nsight Compute 检查：占用率、内存吞吐量、共享内存 bank 冲突
