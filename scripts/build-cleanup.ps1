# build-cleanup.ps1
# 构建产物清理脚本 - Windows PowerShell 版本
# 生成时间：2026-05-21

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "WhirPlonk 构建产物清理脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 获取项目根目录
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

# 确认操作
$confirm = Read-Host "即将删除所有可再生构建产物，是否继续？(y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-Host "已取消操作" -ForegroundColor Yellow
    exit 0
}

$deletedCount = 0
$freedSpace = 0

Write-Host ""
Write-Host "[1/6] 删除 CMake 构建目录..." -ForegroundColor Green

# 删除 CMake 构建目录
$cmakeDirs = @(
    "cpp\build_cpu",
    "cpp\build_cuda",
    "cpp\build_cross_language_golden",
    "cpp\build_cuda_test"
)

foreach ($dir in $cmakeDirs) {
    if (Test-Path $dir) {
        $size = (Get-ChildItem -Path $dir -Recurse -File | Measure-Object -Property Length -Sum).Sum
        Write-Host "  删除: $dir ({0:N2} MB)" -f ($size / 1MB)
        Remove-Item -Recurse -Force $dir
        $deletedCount++
        $freedSpace += $size
    }
}

Write-Host ""
Write-Host "[2/6] 删除 Rust 构建缓存..." -ForegroundColor Green

if (Test-Path "rust\target") {
    $size = (Get-ChildItem -Path "rust\target" -Recurse -File | Measure-Object -Property Length -Sum).Sum
    Write-Host "  删除: rust\target ({0:N2} GB)" -f ($size / 1GB)
    Remove-Item -Recurse -Force "rust\target"
    $deletedCount++
    $freedSpace += $size
}

Write-Host ""
Write-Host "[3/6] 删除 Python 缓存..." -ForegroundColor Green

# 删除所有 __pycache__ 目录
Get-ChildItem -Path . -Recurse -Directory -Filter "__pycache__" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Recurse -Force $_.FullName
    $deletedCount++
}

# 删除 .pyc 文件
Get-ChildItem -Path . -Recurse -File -Filter "*.pyc" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

Write-Host ""
Write-Host "[4/6] 删除二进制产物文件..." -ForegroundColor Green

# 删除可执行文件（排除 .git 目录）
Get-ChildItem -Path . -Recurse -File -Filter "*.exe" | Where-Object {
    $_.FullName -notlike "*\.git\*"
} | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

# 删除对象文件
Get-ChildItem -Path . -Recurse -File -Filter "*.obj" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

# 删除库文件
Get-ChildItem -Path . -Recurse -File -Filter "*.lib" | Where-Object {
    $_.FullName -notlike "*\.git\*"
} | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

# 删除导出文件
Get-ChildItem -Path . -Recurse -File -Filter "*.exp" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

# 删除调试文件
Get-ChildItem -Path . -Recurse -File -Filter "*.pdb" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

# 删除增量链接文件
Get-ChildItem -Path . -Recurse -File -Filter "*.ilk" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

Write-Host ""
Write-Host "[5/6] 删除 CMake 缓存文件..." -ForegroundColor Green

Get-ChildItem -Path . -Recurse -File -Filter "CMakeCache.txt" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

Get-ChildItem -Path . -Recurse -File -Filter "compile_commands.json" | ForEach-Object {
    Write-Host "  删除: $($_.FullName)"
    Remove-Item -Force $_.FullName
    $deletedCount++
}

Write-Host ""
Write-Host "[6/6] 删除 IDE 临时文件..." -ForegroundColor Green

# JetBrains IDE 文件（可选）
if (Test-Path ".idea") {
    $deleteIdea = Read-Host "是否删除 .idea 目录？(y/N)"
    if ($deleteIdea -eq 'y' -or $deleteIdea -eq 'Y') {
        $size = (Get-ChildItem -Path ".idea" -Recurse -File | Measure-Object -Property Length -Sum).Sum
        Write-Host "  删除: .idea ({0:N2} KB)" -f ($size / 1KB)
        Remove-Item -Recurse -Force ".idea"
        $deletedCount++
        $freedSpace += $size
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "清理完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "删除项目数: $deletedCount" -ForegroundColor Yellow
Write-Host "释放空间: {0:N2} GB" -f ($freedSpace / 1GB) -ForegroundColor Yellow
Write-Host ""
Write-Host "建议接下来：" -ForegroundColor Yellow
Write-Host "1. 运行 'git status' 查看变更"
Write-Host "2. 创建 .gitignore 文件防止再次提交构建产物"
Write-Host "3. 使用 out-of-source 构建方式"
