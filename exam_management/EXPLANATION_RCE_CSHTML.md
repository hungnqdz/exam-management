# Giải thích: Tại sao file .cshtml chứa bash script có thể RCE được?

## Câu hỏi

Tại sao khi upload file `rce.cshtml` với nội dung bash script:
```bash
#!/bin/bash
# Đây là file cshtml nhưng chua code bash
touch /tmp/cshtml_fake_thanh_cong
ls -la /tmp > /tmp/ket_qua_check.txt
```

lại có thể thực thi được và gây RCE?

## Giải thích chi tiết

### 1. Luồng xử lý khi upload file `.cshtml`

Khi bạn upload file `rce.cshtml` qua API `/Student/Exam/Submit`, code sẽ thực hiện các bước sau:

**Bước 1: Lưu file**
```csharp
// File được lưu vào wwwroot/uploads/rce.cshtml
var filePath = Path.Combine(uploadsPath, originalFileName);
using (var stream = new FileStream(filePath, FileMode.Create))
{
    await pdfFile.CopyToAsync(stream);
}
```

**Bước 2: Kiểm tra extension**
```csharp
var extension = Path.GetExtension(originalFileName).ToLower();
if (extension == ".cshtml")
{
    // Execute file
}
```

**Bước 3: Execute file**
```csharp
var cshtmlContent = await System.IO.File.ReadAllTextAsync(filePath);
var result = await ExecuteCshtmlAsync(cshtmlContent, filePath);
```

### 2. Code trong method `ExecuteCshtmlAsync`

Đây là code hiện tại trong `StudentController.cs`:

```csharp
private async Task<string> ExecuteCshtmlAsync(string cshtmlContent, string filePath)
{
    try
    {
        // Thử execute bằng dotnet-script
        var processInfo = new ProcessStartInfo
        {
            FileName = "dotnet-script",
            Arguments = $"\"{filePath}\"",
            // ...
        };
        Process.Start(processInfo);
    }
    catch (Exception ex)
    {
        // ⚠️ VULNERABILITY: Fallback sang bash/sh
        try
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"\"{filePath}\"",  // ⚠️ Execute file trực tiếp!
                // ...
            };
            Process.Start(processInfo);
        }
        catch { }
    }
}
```

### 3. Tại sao bash script có thể execute được?

**Nguyên nhân chính: Fallback Logic**

1. **Thử execute bằng `dotnet-script`:**
   - `dotnet-script "rce.cshtml"` sẽ cố gắng execute file như C# script
   - File chứa bash script, không phải C# → **FAIL**
   - Throw exception

2. **Fallback sang `/bin/bash`:**
   - Catch exception và thử execute bằng bash
   - `/bin/bash "rce.cshtml"` sẽ execute file này
   - Bash đọc file và thấy shebang `#!/bin/bash` → **BIẾT ĐÂY LÀ BASH SCRIPT**
   - Bash execute file như bash script → **RCE!**

### 4. Tại sao bash có thể execute file này?

**Bash hoạt động như sau:**

1. **Đọc shebang (hashbang):**
   - Dòng đầu tiên: `#!/bin/bash`
   - Bash nhận ra đây là bash script

2. **Execute file:**
   - Bash đọc toàn bộ file
   - Thực thi các lệnh bash trong file
   - Không cần file có extension `.sh` - chỉ cần có shebang

3. **Kết quả:**
   ```bash
   touch /tmp/cshtml_fake_thanh_cong  # Tạo file
   ls -la /tmp > /tmp/ket_qua_check.txt  # List directory và ghi vào file
   ```
   → **RCE thành công!**

### 5. Vấn đề bảo mật

**Đây là lỗ hổng nghiêm trọng vì:**

1. **Không validate nội dung file:**
   - Code chỉ kiểm tra extension `.cshtml`
   - Không kiểm tra nội dung file có phải C# hợp lệ hay không
   - Cho phép upload bất kỳ nội dung nào, miễn là có extension `.cshtml`

2. **Fallback logic nguy hiểm:**
   - Nếu `dotnet-script` fail, code sẽ thử execute bằng bash
   - Bash có thể execute bất kỳ script nào (bash, sh, python, perl, etc.)
   - Điều này tạo ra lỗ hổng **Command Injection** và **RCE**

3. **Shebang trong file:**
   - File có shebang `#!/bin/bash` → bash biết cách execute
   - Bash không quan tâm đến extension file
   - Chỉ cần file có shebang hợp lệ là có thể execute

### 6. Flow hoàn chỉnh

```
1. Upload file rce.cshtml (chứa bash script)
   ↓
2. File được lưu vào wwwroot/uploads/rce.cshtml
   ↓
3. Code kiểm tra extension == ".cshtml" → TRUE
   ↓
4. Gọi ExecuteCshtmlAsync()
   ↓
5. Thử execute bằng dotnet-script "rce.cshtml"
   → FAIL (file không phải C# script)
   ↓
6. Catch exception → Fallback sang /bin/bash "rce.cshtml"
   ↓
7. Bash đọc file và thấy #!/bin/bash
   ↓
8. Bash execute file như bash script
   ↓
9. Commands được thực thi:
   - touch /tmp/cshtml_fake_thanh_cong
   - ls -la /tmp > /tmp/ket_qua_check.txt
   ↓
10. RCE thành công! ✅
```

### 7. Cách khắc phục

**Cách 1: Không có fallback logic**
```csharp
private async Task<string> ExecuteCshtmlAsync(string cshtmlContent, string filePath)
{
    // Chỉ execute bằng dotnet-script, không có fallback
    var processInfo = new ProcessStartInfo
    {
        FileName = "dotnet-script",
        Arguments = $"\"{filePath}\"",
        // ...
    };
    Process.Start(processInfo);
    // Nếu fail thì fail, không fallback
}
```

**Cách 2: Validate nội dung file**
```csharp
// Kiểm tra file có chứa C# code hợp lệ
if (!cshtmlContent.Contains("@") && !cshtmlContent.Contains("using"))
{
    throw new Exception("File không phải C#/Razor hợp lệ");
}
```

**Cách 3: Không execute file upload**
```csharp
// Không execute file upload, chỉ lưu file
// Chỉ execute file qua endpoint riêng với validation nghiêm ngặt
```

### 8. Kết luận

**Lý do RCE thành công:**

1. ✅ File có extension `.cshtml` → Pass validation
2. ✅ Code có fallback logic: `dotnet-script` fail → try `bash`
3. ✅ File có shebang `#!/bin/bash` → Bash biết cách execute
4. ✅ Bash execute file → RCE!

**Đây là lỗ hổng nghiêm trọng vì:**
- Cho phép execute bất kỳ code nào (bash, sh, python, perl, etc.)
- Không validate nội dung file
- Fallback logic tạo ra attack surface lớn
- Không giới hạn loại script có thể execute

**Cách tốt nhất:**
- ❌ Không nên có fallback logic
- ✅ Validate nội dung file trước khi execute
- ✅ Chỉ cho phép execute C# code hợp lệ
- ✅ Hoặc không execute file upload (chỉ lưu file)

