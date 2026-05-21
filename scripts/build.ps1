# build.ps1
# 统一构建脚本 - Windows PowerShell 版本
# 生成时间：2026-05-21

param(
    [Parameter(Position=0)]
    [ValidateSet('cpu', 'cuda', 'rust', 'all', 'clean', 'test')]
    [string]$Command
)

$ProjectRoot = Split-Path -Parent $PSScriptRoot

# 显示帮助信息
function Show-Help {
    Write-Host "用法: .\build.ps1 <命令>"
    Write-Host ""
    Write-Host "命令："
    Write-Host "  cpu     - 构建 C++ CPU 版本"
    Write-Host "  cuda    - 构建 C++ CUDA 版本"
    Write-Host "  rust    - 构建 Rust 版本"
    Write-Host "  all     - 构建所有版本"
    Write-Host "  clean   - 清理所有构建产物"
    Write-Host "  test    - 运行所有测试"
    Write-Host ""
}

# C++ CPU 构建
function Build-CppCpu {
    Write-Host "构建 C++ CPU 版本..." -ForegroundColor Green
    Set-Location "$ProjectRoot\cpp"
    if (!(Test-Path "build_cpu")) {
        New-Item -ItemType Directory -Path "build_cpu" | Out-Null
    }
    Set-Location "build_cpu"
    cmake -DCMAKE_BUILD_TYPE=Release ..
    cmake --build . --config Release
    Write-Host "完成！可执行文件位于: cpp\build_cpu\Release\" -ForegroundColor Green
}

# C++ CUDA 构建
function Build-CppCuda {
    Write-Host "构建 C++ CUDA 版本..." -ForegroundColor Green
    Set-Location "$ProjectRoot\cpp"
    if (!(Test-Path "build_cuda")) {
        New-Item -ItemType Directory -Path "build_cuda" | Out-Null
    }
    Set-Location "build_cuda"
    cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_CUDA=ON ..
    cmake --build . --config Release
    Write-Host "完成！可执行文件位于: cpp\build_cuda\Release\" -ForegroundColor Green
}

# Rust 构建
function Build-Rust {
    Write-Host "构建 Rust 版本..." -ForegroundColor Green
    Set-Location "$ProjectRoot\rust"
    cargo build --release
    Write-Host "完成！可执行文件位于: rust\target\release\" -ForegroundColor Green
}

# 全部构建
function Build-All {
    Build-CppCpu
    Build-CppCuda
    Build-Rust
}

# 清理构建产物
function Clear-All {
    Write-Host "清理所有构建产物..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "$ProjectRoot\cpp\build_cpu" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$ProjectRoot\cpp\build_cuda" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$ProjectRoot\cpp\build_cross_language_golden" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$ProjectRoot\cpp\build_cuda_test" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$ProjectRoot\rust\target" -ErrorAction SilentlyContinue
    Get-ChildItem -Path $ProjectRoot -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $ProjectRoot -Recurse -File -Filter "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host "清理完成！" -ForegroundColor Green
}

# 运行测试
function Invoke-Tests {
    Write-Host "运行测试..." -ForegroundColor Green

    # C++ 测试
    if (Test-Path "$ProjectRoot\cpp\build_cpu") {
        Write-Host "运行 C++ CPU 测试..." -ForegroundColor Cyan
        Set-Location "$ProjectRoot\cpp\build_cpu"
        ctest --output-on-failure
    }

    # Rust 测试
    Write-Host "运行 Rust 测试..." -ForegroundColor Cyan
    Set-Location "$ProjectRoot\rust"
    cargo test

    Write-Host "测试完成！" -ForegroundColor Green
}

# 主函数
if (!$Command) {
    Show-Help
    exit 1
}

switch ($Command) {
    'cpu' { Build-CppCpu }
    'cuda' { Build-CppCuda }
    'rust' { Build-Rust }
    'all' { Build-All }
    'clean' { Clear-All }
    'test' { Invoke-Tests }
}
