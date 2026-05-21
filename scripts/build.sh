#!/bin/bash
# build.sh
# 统一构建脚本
# 生成时间：2026-05-21

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 显示帮助信息
show_help() {
    echo "用法: $0 {cpu|cuda|rust|all|clean|test}"
    echo ""
    echo "命令："
    echo "  cpu     - 构建 C++ CPU 版本"
    echo "  cuda    - 构建 C++ CUDA 版本"
    echo "  rust    - 构建 Rust 版本"
    echo "  all     - 构建所有版本"
    echo "  clean   - 清理所有构建产物"
    echo "  test    - 运行所有测试"
    echo ""
}

# C++ CPU 构建
build_cpp_cpu() {
    echo -e "${GREEN}构建 C++ CPU 版本...${NC}"
    cd "$PROJECT_ROOT/cpp"
    mkdir -p build_cpu && cd build_cpu
    cmake -DCMAKE_BUILD_TYPE=Release ..
    cmake --build . --config Release
    echo -e "${GREEN}完成！可执行文件位于: cpp/build_cpu/Release/${NC}"
}

# C++ CUDA 构建
build_cpp_cuda() {
    echo -e "${GREEN}构建 C++ CUDA 版本...${NC}"
    cd "$PROJECT_ROOT/cpp"
    mkdir -p build_cuda && cd build_cuda
    cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_CUDA=ON ..
    cmake --build . --config Release
    echo -e "${GREEN}完成！可执行文件位于: cpp/build_cuda/Release/${NC}"
}

# Rust 构建
build_rust() {
    echo -e "${GREEN}构建 Rust 版本...${NC}"
    cd "$PROJECT_ROOT/rust"
    cargo build --release
    echo -e "${GREEN}完成！可执行文件位于: rust/target/release/${NC}"
}

# 全部构建
build_all() {
    build_cpp_cpu
    build_cpp_cuda
    build_rust
}

# 清理构建产物
clean_all() {
    echo -e "${YELLOW}清理所有构建产物...${NC}"
    rm -rf "$PROJECT_ROOT/cpp/build_cpu"
    rm -rf "$PROJECT_ROOT/cpp/build_cuda"
    rm -rf "$PROJECT_ROOT/cpp/build_cross_language_golden"
    rm -rf "$PROJECT_ROOT/cpp/build_cuda_test"
    rm -rf "$PROJECT_ROOT/rust/target"
    find "$PROJECT_ROOT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$PROJECT_ROOT" -type f -name "*.pyc" -delete 2>/dev/null || true
    echo -e "${GREEN}清理完成！${NC}"
}

# 运行测试
run_tests() {
    echo -e "${GREEN}运行测试...${NC}"

    # C++ 测试
    if [ -d "$PROJECT_ROOT/cpp/build_cpu" ]; then
        echo -e "${CYAN}运行 C++ CPU 测试...${NC}"
        cd "$PROJECT_ROOT/cpp/build_cpu"
        ctest --output-on-failure
    fi

    # Rust 测试
    echo -e "${CYAN}运行 Rust 测试...${NC}"
    cd "$PROJECT_ROOT/rust"
    cargo test

    echo -e "${GREEN}测试完成！${NC}"
}

# 主函数
case "$1" in
    cpu)
        build_cpp_cpu
        ;;
    cuda)
        build_cpp_cuda
        ;;
    rust)
        build_rust
        ;;
    all)
        build_all
        ;;
    clean)
        clean_all
        ;;
    test)
        run_tests
        ;;
    *)
        show_help
        exit 1
        ;;
esac
