#!/usr/bin/env python3
"""Compare line-oriented C++ and Rust golden dump outputs.

Dump files are expected to contain lines of the form:

    label value...

Indented lines are accepted. Lines starting with "#" are ignored.
The script reports exact matches and the first byte/character divergence.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


DEFAULT_REQUIRED = (
    "input_vector0",
    "f_hat_vector0",
    "blinding_m_poly0",
    "blinding_vector0",
    "check_eof",
)

DEFAULT_OBSERVED = (
    "proof_narg",
    "proof_hints",
    "verify",
)


def parse_dump(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        label, sep, value = stripped.partition(" ")
        if not sep:
            raise ValueError(f"{path}:{line_no}: expected 'label value' line")
        values[label] = value.strip()
    return values


def common_prefix_len(left: str, right: str) -> int:
    prefix = 0
    for a, b in zip(left, right):
        if a != b:
            break
        prefix += 1
    return prefix


def compare_label(label: str, cpp: dict[str, str], rust: dict[str, str]) -> tuple[bool, str]:
    if label not in cpp or label not in rust:
        return False, f"{label}: missing cpp={label in cpp} rust={label in rust}"

    left = cpp[label]
    right = rust[label]
    if left == right:
        return True, f"{label}: equal len={len(left)}"

    prefix = common_prefix_len(left, right)
    return (
        False,
        "\n".join(
            (
                f"{label}: DIFFER cpp_len={len(left)} rust_len={len(right)} common_prefix={prefix}",
                f"  cpp_first_diff={left[prefix:prefix + 96]}",
                f"  rust_first_diff={right[prefix:prefix + 96]}",
            )
        ),
    )


def parse_labels(raw: str | None, defaults: tuple[str, ...]) -> tuple[str, ...]:
    if raw is None:
        return defaults
    if raw == "":
        return ()
    return tuple(label.strip() for label in raw.split(",") if label.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare C++ and Rust cross-language dumps")
    parser.add_argument("--cpp", required=True, type=Path, help="C++ dump file")
    parser.add_argument("--rust", required=True, type=Path, help="Rust dump file")
    parser.add_argument(
        "--required",
        default=None,
        help="Comma-separated labels that must be byte-for-byte equal",
    )
    parser.add_argument(
        "--observed",
        default=None,
        help="Comma-separated labels to report without failing on mismatch",
    )
    args = parser.parse_args()

    cpp = parse_dump(args.cpp)
    rust = parse_dump(args.rust)
    required = parse_labels(args.required, DEFAULT_REQUIRED)
    observed = parse_labels(args.observed, DEFAULT_OBSERVED)

    failed = False
    print("# required")
    for label in required:
        equal, message = compare_label(label, cpp, rust)
        print(message)
        failed = failed or not equal

    if observed:
        print("# observed")
    for label in observed:
        _equal, message = compare_label(label, cpp, rust)
        print(message)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
