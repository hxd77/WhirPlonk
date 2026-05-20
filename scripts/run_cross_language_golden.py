#!/usr/bin/env python3
"""Run cross-language golden dump checks for C++ and Rust WHIR artifacts."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path


WHIR_ZK_REQUIRED = (
    "canonical_config",
    "ds_protocol_id",
    "ds_session_id",
    "input_vector0",
    "f_hat_vector0",
    "blinding_m_poly0",
    "blinding_vector0",
    "proof_narg",
    "proof_hints",
    "verify",
    "check_eof",
)

WHIR_ZK_OBSERVED = ("rust_real_ds_protocol_id",)
WINDOWS_ACCESS_VIOLATION = 0xC0000005


def run(cmd: list[str], cwd: Path, *, stdout: Path | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    if stdout is None:
        subprocess.run(cmd, cwd=cwd, check=True)
        return

    stdout.parent.mkdir(parents=True, exist_ok=True)
    with stdout.open("wb") as out:
        subprocess.run(cmd, cwd=cwd, check=True, stdout=out)


def run_cpp_dumper(cmd: list[str], cwd: Path) -> None:
    try:
        run(cmd, cwd)
    except subprocess.CalledProcessError as error:
        if os.name != "nt" or error.returncode != WINDOWS_ACCESS_VIOLATION:
            raise
        print("C++ dumper hit Windows access violation; retrying once.", flush=True)
        run(cmd, cwd)


def exe_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def remove_tree(path: Path) -> None:
    def make_writable_and_retry(function, failed_path, _exc_info) -> None:
        os.chmod(failed_path, stat.S_IWRITE)
        function(failed_path)

    shutil.rmtree(path, onerror=make_writable_and_retry)


def configure_cpp(repo: Path, build_dir: Path, generator: str | None) -> None:
    cmd = [
        "cmake",
        "-S",
        "cpp",
        "-B",
        str(build_dir),
        "-DWHIR_BUILD_TESTS=ON",
        "-DWHIR_CUDA=OFF",
        "-DWHIR_BLAKE3_SIMD=OFF",
    ]
    if generator:
        cmd[5:5] = ["-G", generator]
    run(cmd, repo)


def build_cpp(repo: Path, build_dir: Path, target: str) -> None:
    run(["cmake", "--build", str(build_dir), "--target", target, "-j", "4"], repo)


def run_whir_zk(repo: Path, build_dir: Path, output_root: Path) -> None:
    cpp_output = output_root / "cpp_output" / "whir_zk_dump.txt"
    rust_output = output_root / "rust_output" / "whir_zk_dump.txt"
    diff_output = output_root / "diff" / "whir_zk.diff.txt"

    cpp_exe = build_dir / "tests" / exe_name("dump_whir_zk")
    cpp_output.parent.mkdir(parents=True, exist_ok=True)
    run_cpp_dumper([str(cpp_exe), str(cpp_output)], repo)
    run(
        [
            "cargo",
            "run",
            "--manifest-path",
            "rust/Cargo.toml",
            "--example",
            "dump_whir_zk",
            "--no-default-features",
        ],
        repo,
        stdout=rust_output,
    )

    compare_cmd = [
        sys.executable,
        "scripts/compare_cross_language_dumps.py",
        "--cpp",
        str(cpp_output),
        "--rust",
        str(rust_output),
        "--required",
        ",".join(WHIR_ZK_REQUIRED),
        "--observed",
        ",".join(WHIR_ZK_OBSERVED),
    ]
    print("+", " ".join(compare_cmd), flush=True)
    diff_output.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        compare_cmd,
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    diff_output.write_text(completed.stdout, encoding="utf-8")
    print(completed.stdout, end="")
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, compare_cmd)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--case",
        choices=("whir_zk",),
        default="whir_zk",
        help="Golden check case to run",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("cpp/build_cross_language_golden"),
        help="C++ CMake build directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tests/cross_language/whir_zk"),
        help="Directory for generated C++/Rust dumps and diff reports",
    )
    parser.add_argument(
        "--generator",
        default="MinGW Makefiles" if os.name == "nt" else None,
        help="CMake generator. Use an empty string for CMake's default generator.",
    )
    parser.add_argument("--skip-build", action="store_true", help="Reuse an existing C++ build")
    parser.add_argument("--clean", action="store_true", help="Remove build and output dirs first")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(__file__).resolve().parents[1]
    build_dir = args.build_dir
    output_dir = args.output_dir
    if not build_dir.is_absolute():
        build_dir = repo / build_dir
    if not output_dir.is_absolute():
        output_dir = repo / output_dir

    if args.clean:
        for path in (build_dir, output_dir):
            if path.exists():
                resolved = path.resolve()
                if repo not in (resolved, *resolved.parents):
                    raise RuntimeError(f"refusing to remove outside repo: {resolved}")
                remove_tree(resolved)

    generator = args.generator or None
    if not args.skip_build:
        configure_cpp(repo, build_dir, generator)
        build_cpp(repo, build_dir, "dump_whir_zk")

    if args.case == "whir_zk":
        run_whir_zk(repo, build_dir, output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
