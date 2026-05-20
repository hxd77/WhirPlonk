import pandas as pd
import matplotlib.pyplot as plt


def load_data(excel_path):
    """
    读取清洗后的 Excel 数据
    """
    df = pd.read_excel(excel_path, sheet_name="Cleaned_Data")
    df = df.sort_values(by=["gpu_model", "input_size"])
    return df


def plot_cpu_gpu_total_time(df):
    """
    图 1：CPU、T400、RTX 4090 总耗时对比
    """
    plt.figure(figsize=(10, 6))

    # CPU 时间：两台机器各自都有 CPU 时间
    for gpu in df["gpu_model"].unique():
        sub = df[df["gpu_model"] == gpu]

        plt.plot(
            sub["input_size"],
            sub["cpu_ms"],
            marker="o",
            linestyle="--",
            label=f"CPU on {gpu} machine"
        )

        plt.plot(
            sub["input_size"],
            sub["gpu_total_ms"],
            marker="s",
            linestyle="-",
            label=f"GPU Total on {gpu}"
        )

    plt.xscale("log", base=2)
    plt.yscale("log")

    plt.xlabel("Input Size")
    plt.ylabel("Time (ms)")
    plt.title("CPU vs GPU End-to-End Time Comparison")
    plt.legend()
    plt.grid(True, which="both", linestyle="--", linewidth=0.5)

    plt.tight_layout()
    plt.savefig("cpu_gpu_total_time_comparison.png", dpi=300)
    plt.show()


def plot_cpu_gpu_speedup(df):
    """
    图 2：CPU 相对 GPU 的端到端加速比
    speedup = cpu_ms / gpu_total_ms
    """
    plt.figure(figsize=(10, 6))

    for gpu in df["gpu_model"].unique():
        sub = df[df["gpu_model"] == gpu]

        speedup = sub["cpu_ms"] / sub["gpu_total_ms"]

        plt.plot(
            sub["input_size"],
            speedup,
            marker="o",
            label=f"{gpu} End-to-End Speedup"
        )

    plt.xscale("log", base=2)

    plt.xlabel("Input Size")
    plt.ylabel("Speedup over CPU")
    plt.title("CPU to GPU End-to-End Speedup")
    plt.legend()
    plt.grid(True, which="both", linestyle="--", linewidth=0.5)

    plt.tight_layout()
    plt.savefig("cpu_gpu_end_to_end_speedup.png", dpi=300)
    plt.show()


def main():
    excel_path = r"C:\Users\DELL\Downloads\ntt_gpu_benchmark_cleaned_t400_vs_4090.xlsx"

    df = load_data(excel_path)

    print("Loaded data:")
    print(df)

    plot_cpu_gpu_total_time(df)
    plot_cpu_gpu_speedup(df) 


if __name__ == "__main__":
    main()