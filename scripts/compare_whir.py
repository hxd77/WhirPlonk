#!/usr/bin/env python3
"""
WHIR Rust vs C++ 输入输出一致性验证脚本

用法:
  python compare_whir.py [--cases cases.json] [--tolerance 0.05]

功能:
  1. 用相同的参数组合运行 Rust 和 C++ 版本的 WHIR
  2. 提取证明大小 (Proof Size) 和验证结果
  3. 进行断言比对 (Assert) 并生成差异报告

要求:
  - Rust: cargo build --release  (生成 target/release/main)
  - C++:  cmake --build build_omp --target whir_cli (生成 whir_cli)
"""

import subprocess
import json
import sys
import os
import re
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# 默认测试用例 — 覆盖主要的参数组合
DEFAULT_CASES = [
    # (描述, 参数列表)
    ("默认参数 (Goldilocks3, Blake3)", []),
    ("Goldilocks1 + Sha2", ["-f", "Goldilocks1", "--hash", "Sha2"]),
    ("Goldilocks2 + Blake3, rate=2", ["-f", "Goldilocks2", "-r", "2"]),
    ("小规模 2^16, fold=2", ["-d", "16", "-k", "2", "-i", "2"]),
    ("高安全 200bit, pow=30", ["-l", "200", "-p", "30"]),
    ("多求值点 evaluations=3", ["-e", "3"]),
    ("唯一解码 unique-decoding", ["--unique-decoding"]),
    ("大折叠因子 fold=8", ["-d", "18", "-k", "8", "-i", "8"]),
]

# 输出中需要提取的关键指标
METRIC_PATTERNS = {
    "prover_time_ms": re.compile(r"Prover time:\s*([\d.]+)ms\s*\+\s*([\d.]+)ms\s*=\s*([\d.]+)ms"),
    "proof_size_kib": re.compile(r"Proof size:\s*([\d.]+)\s*KiB"),
    "verifier_time_ms": re.compile(r"Verifier time:\s*([\d.]+)ms"),
    "security_bits": re.compile(r"Security level:\s*([\d.]+)\s*bits"),
    "field_hash": re.compile(r"Field:\s*(\S+)\s*and hash:\s*(\S+)"),
    # C++ 特有: 行尾可能有 " — C++"
    "prover_time_cpp": re.compile(r"Prover time:\s*([\d.]+)ms\s*\+\s*([\d.]+)ms\s*=\s*([\d.]+)ms"),
    "proof_size_cpp": re.compile(r"Proof size:\s*([\d.]+)\s*KiB"),
    "verifier_time_cpp": re.compile(r"Verifier time:\s*([\d.]+)ms"),
}


def find_binary(name: str) -> Path:
    """查找编译产物"""
    # Rust
    rust_path = PROJECT_ROOT / "target" / "release" / name
    if rust_path.exists():
        return rust_path
    # 带 .exe 后缀 (Windows)
    rust_exe = rust_path.with_suffix(".exe")
    if rust_exe.exists():
        return rust_exe
    # C++
    for build_dir in ["build_omp", "build", "build_release"]:
        cpp_path = PROJECT_ROOT / "cpp" / build_dir / name
        if cpp_path.exists():
            return cpp_path
        cpp_exe = cpp_path.with_suffix(".exe")
        if cpp_exe.exists():
            return cpp_exe
    return None


def run_whir(binary: Path, extra_args: list[str] | None = None) -> dict:
    """运行 WHIR 并解析输出"""
    args = [str(binary)]
    if extra_args:
        args.extend(extra_args)

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=600,  # 10 分钟超时
            cwd=PROJECT_ROOT,
        )
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "stdout": "", "stderr": ""}
    except FileNotFoundError:
        return {"error": "binary_not_found", "stdout": "", "stderr": ""}

    stdout = result.stdout
    stderr = result.stderr

    metrics = {"stdout": stdout, "stderr": stderr, "returncode": result.returncode}

    # 解析 Prover 时间: "Prover time: Xms + Yms = Zms"
    m = re.search(r"Prover time:\s*([\d.]+)ms\s*\+\s*([\d.]+)ms\s*=\s*([\d.]+)ms", stdout)
    if m:
        metrics["commit_ms"] = float(m.group(1))
        metrics["prove_ms"] = float(m.group(2))
        metrics["total_prover_ms"] = float(m.group(3))

    # 解析 Proof 大小
    m = re.search(r"Proof size:\s*([\d.]+)\s*KiB", stdout)
    if m:
        metrics["proof_kib"] = float(m.group(1))

    # 解析 Verifier 时间
    m = re.search(r"Verifier time:\s*([\d.]+)ms", stdout)
    if m:
        metrics["verifier_ms"] = float(m.group(1))

    # 解析 Average hashes
    m = re.search(r"Average hashes:\s*([\d.]+)k", stdout)
    if m:
        metrics["avg_hashes_k"] = float(m.group(1))

    # 解析安全级别
    m = re.search(r"Security level:\s*([\d.]+)\s*bits", stdout)
    if m:
        metrics["security_bits"] = float(m.group(1))

    return metrics


def compare_results(rust: dict, cpp: dict, tolerance: float = 0.05) -> list[str]:
    """比对两个结果，返回差异列表"""
    diffs = []

    # 检查基本错误
    if "error" in rust:
        diffs.append(f"Rust 运行失败: {rust['error']}")
    if "error" in cpp:
        diffs.append(f"C++ 运行失败: {cpp['error']}")

    if "error" in rust or "error" in cpp:
        return diffs

    # 比对证明大小 (关键指标 - 必须严格一致)
    if "proof_kib" in rust and "proof_kib" in cpp:
        delta = abs(rust["proof_kib"] - cpp["proof_kib"])
        if delta > 0.01:  # 证明大小必须精确一致
            diffs.append(
                f"证明大小不一致: Rust={rust['proof_kib']:.2f} KiB, "
                f"C++={cpp['proof_kib']:.2f} KiB (差 {delta:.2f} KiB)"
            )
    else:
        diffs.append("无法提取证明大小")

    # 比对验证时间 (允许较大误差，因为硬件影响)
    if "verifier_ms" in rust and "verifier_ms" in cpp:
        ratio = max(rust["verifier_ms"], cpp["verifier_ms"]) / max(0.001, min(rust["verifier_ms"], cpp["verifier_ms"]))
        if ratio > 2.0:  # 不应超过 2x
            diffs.append(
                f"验证时间差异过大: Rust={rust['verifier_ms']:.2f}ms, "
                f"C++={cpp['verifier_ms']:.2f}ms (ratio={ratio:.1f}x)"
            )

    # 比对平均哈希数 (应该一致，因为协议是确定性的)
    if "avg_hashes_k" in rust and "avg_hashes_k" in cpp:
        delta = abs(rust["avg_hashes_k"] - cpp["avg_hashes_k"])
        if delta > 1.0:
            diffs.append(
                f"平均哈希数不一致: Rust={rust['avg_hashes_k']:.1f}k, "
                f"C++={cpp['avg_hashes_k']:.1f}k"
            )

    return diffs


def print_header(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="WHIR Rust vs C++ 一致性验证")
    parser.add_argument("--tolerance", type=float, default=0.05,
                        help="数值容差 (默认 0.05)")
    parser.add_argument("--cases", type=str, default=None,
                        help="JSON 测试用例文件路径")
    parser.add_argument("--rust-bin", type=str, default=None,
                        help="Rust 二进制路径")
    parser.add_argument("--cpp-bin", type=str, default=None,
                        help="C++ 二进制路径")
    parser.add_argument("--list", action="store_true",
                        help="仅列出测试用例")
    args_parsed = parser.parse_args()

    # 查找二进制文件
    rust_bin = args_parsed.rust_bin and Path(args_parsed.rust_bin) or find_binary("main")
    cpp_bin = args_parsed.cpp_bin and Path(args_parsed.cpp_bin) or find_binary("whir_cli")

    print_header("WHIR 跨语言一致性验证")
    print(f"  Rust: {rust_bin or '未找到'}")
    print(f"  C++:  {cpp_bin or '未找到'}")

    if not rust_bin:
        print("\n[警告] Rust 二进制未找到。尝试 cargo build --release...")
        try:
            subprocess.run(["cargo", "build", "--release"],
                         cwd=PROJECT_ROOT, check=True)
            rust_bin = find_binary("main")
            print(f"  构建完成: {rust_bin}")
        except Exception as e:
            print(f"  构建失败: {e}")

    if not cpp_bin:
        print("\n[警告] C++ 二进制未找到。请手动编译后指定 --cpp-bin。")

    if args_parsed.list:
        print_header("测试用例列表")
        for i, (desc, cargs) in enumerate(DEFAULT_CASES):
            print(f"  [{i}] {desc}")
            print(f"      whir {' '.join(cargs)}")
        return

    # 加载测试用例
    if args_parsed.cases:
        with open(args_parsed.cases) as f:
            cases = json.load(f)
    else:
        cases = DEFAULT_CASES

    # 运行测试
    passed = 0
    failed = 0

    for i, case in enumerate(cases):
        if isinstance(case, (list, tuple)):
            desc, cargs = case[0], case[1]
        else:
            desc, cargs = case.get("name", f"case_{i}"), case.get("args", [])

        print_header(f"[{i}] {desc}")
        print(f"  参数: {' '.join(cargs)}")

        rust_result = {}
        cpp_result = {}

        if rust_bin:
            rust_result = run_whir(rust_bin, cargs)
            if "error" not in rust_result:
                print(f"  Rust:  Prover={rust_result.get('total_prover_ms', '?')}ms  "
                      f"Proof={rust_result.get('proof_kib', '?')} KiB  "
                      f"Verifier={rust_result.get('verifier_ms', '?')}ms")
            else:
                print(f"  Rust: 错误 — {rust_result['error']}")

        if cpp_bin:
            cpp_result = run_whir(cpp_bin, cargs)
            if "error" not in cpp_result:
                print(f"  C++:   Prover={cpp_result.get('total_prover_ms', '?')}ms  "
                      f"Proof={cpp_result.get('proof_kib', '?')} KiB  "
                      f"Verifier={cpp_result.get('verifier_ms', '?')}ms")
            else:
                print(f"  C++:  错误 — {cpp_result['error']}")

        if rust_bin and cpp_bin:
            diffs = compare_results(rust_result, cpp_result, args_parsed.tolerance)
            if diffs:
                print(f"  [失败] 发现 {len(diffs)} 处差异:")
                for d in diffs:
                    print(f"    - {d}")
                failed += 1
            else:
                print(f"  [通过] 输出一致")
                passed += 1

    # 汇总
    print_header("汇总")
    print(f"  通过: {passed}/{passed + failed}")
    if failed > 0:
        print(f"  失败: {failed} 个用例")
        sys.exit(1)
    else:
        print("  全部通过!")


if __name__ == "__main__":
    main()
