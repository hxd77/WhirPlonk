# 跨语言基准校验
该目录供`scripts/run_cross_language_golden.py`脚本使用，用于存放生成的C++、Rust协议转储文件与差异对比报告。

在代码库根目录执行当前WHIR-ZK三级校验：
```powershell
python scripts\run_cross_language_golden.py --clean
```

生成的文件将存放至以下路径：
- `tests/cross_language/whir_zk/cpp_output/`
- `tests/cross_language/whir_zk/rust_output/`
- `tests/cross_language/whir_zk/diff/`

本次校验的WHIR-ZK相关指标包含标准配置字节、交互协议域标识、确定性零知识盲化向量、序列化证明字节以及验证器通过/文件结束校验结果。