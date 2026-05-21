#!/bin/bash
# build-cleanup.sh
# 构建产物清理脚本 - Linux/macOS 版本
# 生成时间：2026-05-21

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo "========================================"
echo -e "${CYAN}WhirPlonk 构建产物清理脚本${NC}"
echo "========================================"
echo ""

# 获取项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# 确认操作
read -p "即将删除所有可再生构建产物，是否继续？(y/N) " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo -e "${YELLOW}已取消操作${NC}"
    exit 0
fi

deleted_count=0
freed_space=0

echo ""
echo -e "${GREEN}[1/6] 删除 CMake 构建目录...${NC}"

# 删除 CMake 构建目录
cmake_dirs=(
    "cpp/build_cpu"
    "cpp/build_cuda"
    "cpp/build_cross_language_golden"
    "cpp/build_cuda_test"
)

for dir in "${cmake_dirs[@]}"; do
    if [ -d "$dir" ]; then
        size=$(du -sh "$dir" | cut -f1)
        echo "  删除: $dir ($size)"
        rm -rf "$dir"
        ((deleted_count++))
    fi
done

echo ""
echo -e "${GREEN}[2/6] 删除 Rust 构建缓存...${NC}"

if [ -d "rust/target" ]; then
    size=$(du -sh "rust/target" | cut -f1)
    echo "  删除: rust/target ($size)"
    rm -rf "rust/target"
    ((deleted_count++))
fi

echo ""
echo -e "${GREEN}[3/6] 删除 Python 缓存...${NC}"

# 删除所有 __pycache__ 目录
find . -type d -name "__pycache__" | while read -r dir; do
    echo "  删除: $dir"
    rm -rf "$dir"
    ((deleted_count++))
done

# 删除 .pyc 文件
find . -type f -name "*.pyc" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

echo ""
echo -e "${GREEN}[4/6] 删除二进制产物文件...${NC}"

# 删除可执行文件（排除 .git 目录）
find . -type f -name "*.exe" -not -path "./.git/*" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

# 删除对象文件
find . -type f -name "*.obj" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

# 删除库文件（排除 .git 目录）
find . -type f -name "*.lib" -not -path "./.git/*" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

# 删除导出文件
find . -type f -name "*.exp" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

# 删除调试文件
find . -type f -name "*.pdb" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

# 删除增量链接文件
find . -type f -name "*.ilk" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

echo ""
echo -e "${GREEN}[5/6] 删除 CMake 缓存文件...${NC}"

find . -type f -name "CMakeCache.txt" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

find . -type f -name "compile_commands.json" | while read -r file; do
    echo "  删除: $file"
    rm -f "$file"
    ((deleted_count++))
done

echo ""
echo -e "${GREEN}[6/6] 删除 IDE 临时文件...${NC}"

# JetBrains IDE 文件（可选）
if [ -d ".idea" ]; then
    read -p "是否删除 .idea 目录？(y/N) " delete_idea
    if [[ "$delete_idea" == "y" || "$delete_idea" == "Y" ]]; then
        size=$(du -sh ".idea" | cut -f1)
        echo "  删除: .idea ($size)"
        rm -rf ".idea"
        ((deleted_count++))
    fi
fi

echo ""
echo "========================================"
echo -e "${GREEN}清理完成！${NC}"
echo "========================================"
echo ""
echo -e "${YELLOW}删除项目数: $deleted_count${NC}"
echo ""
echo -e "${YELLOW}建议接下来：${NC}"
echo "1. 运行 'git status' 查看变更"
echo "2. 创建 .gitignore 文件防止再次提交构建产物"
echo "3. 使用 out-of-source 构建方式"
