param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"
$rootPath = (Resolve-Path -LiteralPath $Root).Path.TrimEnd("\")

function Remove-SafePath {
    param([string]$Path)

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) {
        return
    }

    foreach ($item in $resolved) {
        $fullPath = $item.Path
        if (-not ($fullPath -eq $rootPath -or $fullPath.StartsWith($rootPath + "\"))) {
            throw "Refusing to delete outside repository root: $fullPath"
        }
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}

$directoryPatterns = @(
    "build",
    "build_*",
    "cmake-build-*",
    "CMakeFiles",
    ".vs",
    ".cache",
    "__pycache__",
    "target"
)

$filePatterns = @(
    "CMakeCache.txt",
    "compile_commands.json",
    "*.obj",
    "*.o",
    "*.pdb",
    "*.ilk",
    "*.exp",
    "*.lib",
    "*.dll",
    "*.exe",
    "*.ninja",
    ".ninja_deps",
    ".ninja_log",
    "*.pyc"
)

foreach ($pattern in $directoryPatterns) {
    Get-ChildItem -LiteralPath $rootPath -Recurse -Force -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "\\.git(\\|$)" -and $_.Name -like $pattern } |
        Sort-Object FullName -Descending |
        ForEach-Object { Remove-SafePath $_.FullName }
}

foreach ($pattern in $filePatterns) {
    Get-ChildItem -LiteralPath $rootPath -Recurse -Force -File -Filter $pattern -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "\\.git(\\|$)" } |
        ForEach-Object { Remove-SafePath $_.FullName }
}

Write-Host "Generated build artifacts cleaned under $rootPath"
