#!/usr/bin/env python3
"""Plot WHIR profiling CSV emitted by whir_cli --profile or bench_ntt_compare."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def plot_stage_csv(csv_path: Path, out_path: Path) -> None:
    df = pd.read_csv(csv_path)
    if {"mode", "size", "stage", "time_ms"}.issubset(df.columns):
        pivot = df.groupby(["stage", "mode"], as_index=False)["time_ms"].sum()
        labels = [f"{row.stage}\n{row.mode}" for row in pivot.itertuples()]
        values = pivot["time_ms"].to_numpy()
        plt.figure(figsize=(max(10, len(labels) * 0.55), 5))
        plt.bar(labels, values)
        plt.ylabel("time (ms)")
        plt.xticks(rotation=55, ha="right")
        plt.tight_layout()
        plt.savefig(out_path, dpi=160)
        return

    required = {"input_size", "cpu_ms", "gpu_total_ms", "gpu_kernel_ms"}
    if required.issubset(df.columns):
        plt.figure(figsize=(9, 5))
        plt.loglog(df["input_size"], df["cpu_ms"], marker="o", label="CPU NTT")
        plt.loglog(df["input_size"], df["gpu_total_ms"], marker="o", label="GPU total")
        plt.loglog(df["input_size"], df["gpu_kernel_ms"], marker="o", label="GPU kernel")
        if "gpu_h2d_ms" in df:
            plt.loglog(df["input_size"], df["gpu_h2d_ms"], marker=".", label="H2D")
        if "gpu_d2h_ms" in df:
            plt.loglog(df["input_size"], df["gpu_d2h_ms"], marker=".", label="D2H")
        if "gpu_malloc_ms" in df:
            plt.loglog(df["input_size"], df["gpu_malloc_ms"], marker=".", label="malloc")
        plt.xlabel("NTT size")
        plt.ylabel("time (ms)")
        plt.grid(True, which="both", alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_path, dpi=160)
        return

    raise SystemExit(f"Unrecognized CSV columns: {', '.join(df.columns)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("-o", "--out", type=Path, default=Path("whir_profile.png"))
    args = parser.parse_args()
    plot_stage_csv(args.csv, args.out)


if __name__ == "__main__":
    main()
