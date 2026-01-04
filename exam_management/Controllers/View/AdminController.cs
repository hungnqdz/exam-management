using ExamManagement.Models;
using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;

namespace ExamManagement.Controllers.View
{
    [Authorize(Roles = "Admin")]
    [Route("Admin")]
    public class AdminController : Controller
    {
        private readonly IUserService _userService;
        private readonly IWebHostEnvironment _env;

        public AdminController(IUserService userService, IWebHostEnvironment env)
        {
            _userService = userService;
            _env = env;
        }

        private int GetUserId() => int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);

        // Security: Escape CSV values to prevent CSV injection attacks
        private string EscapeCsvValue(string value)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            
            // If value starts with dangerous characters (=, +, -, @, \t, \r), wrap in quotes
            if (value.StartsWith("=") || value.StartsWith("+") || value.StartsWith("-") || 
                value.StartsWith("@") || value.StartsWith("\t") || value.StartsWith("\r"))
            {
                // Escape quotes by doubling them and wrap in quotes
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            
            // If value contains comma, newline, or quote, wrap in quotes
            if (value.Contains(",") || value.Contains("\n") || value.Contains("\"") || value.Contains("\r"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            
            return value;
        }

        // VULNERABILITY: Vertical Privilege Escalation - Bug allows Students to access Admin-only user list
        // But Teachers are blocked (inconsistent authorization logic)
        [AllowAnonymous] // Override class-level [Authorize(Roles = "Admin")] - allows any user (even unauthenticated)
        [HttpGet("")]
        public async Task<IActionResult> Index(string search)
        {
            // VULNERABILITY: Inconsistent authorization - Students can access but Teachers cannot
            // This is a vertical privilege escalation bug
            // Check if user is authenticated
            if (!User.Identity?.IsAuthenticated ?? true)
            {
                return RedirectToAction("Login", "Auth");
            }
            
            var userRole = User.FindFirst(ClaimTypes.Role)?.Value;
            if (userRole == "Teacher")
            {
                return Forbid();
            }
            
            // Security: Sanitize search input
            if (!string.IsNullOrEmpty(search))
            {
                search = search.Trim();
                // Limit search length to prevent DoS
                if (search.Length > 100)
                {
                    search = search.Substring(0, 100);
                }
            }
            
            var users = string.IsNullOrEmpty(search) 
                ? await _userService.GetAllUsersAsync() 
                : await _userService.SearchUsersAsync(search);
            ViewBag.Search = search;
            ViewBag.Subjects = await _userService.GetAllSubjectsAsync();
            return View(users);
        }

        // VULNERABILITY: CSRF - No anti-forgery token validation
        [HttpPost("Create")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Create(CreateUserVm model)
        {
            // Security: Input validation and sanitization
            if (model != null)
            {
                model.Username = (model.Username ?? string.Empty).Trim();
                model.FullName = (model.FullName ?? string.Empty).Trim();
                model.Password = model.Password ?? string.Empty;
            }
            
            // Security: Validate required fields first
            if (model == null || string.IsNullOrWhiteSpace(model.Username) || string.IsNullOrWhiteSpace(model.FullName) || string.IsNullOrWhiteSpace(model.Password))
            {
                ModelState.AddModelError("", "Username, Full Name, and Password are required.");
            }
            else
            {
                // Check username is already taken (case-insensitive check)
                if (await _userService.IsUsernameTakenAsync(model.Username))
                {
                    ModelState.AddModelError("Username", $"Tên đăng nhập '{model.Username}' đã tồn tại. Vui lòng chọn tên đăng nhập khác.");
                }
                
                // Validate password length
                if (model.Password.Length < 6)
                {
                    ModelState.AddModelError("Password", "Mật khẩu phải có ít nhất 6 ký tự.");
                }
            }
            
            // Requirement: Cannot create Admin users
            if (model != null && model.Role == UserRole.Admin)
            {
                ModelState.AddModelError("Role", "Không thể tạo người dùng Admin.");
            }

            if (ModelState.IsValid)
            {
                var user = new User { Username = model.Username, FullName = model.FullName, Role = model.Role };
                try {
                    await _userService.CreateUserAsync(user, model.Password, model.SubjectIds);
                    TempData["Message"] = $"Đã tạo người dùng '{model.Username}' thành công.";
                    return RedirectToAction("Index");
                } catch(Exception ex) {
                    ModelState.AddModelError("", $"Lỗi khi tạo người dùng: {ex.Message}");
                }
            }
            ViewBag.Subjects = await _userService.GetAllSubjectsAsync();
            // Reload data for Index view
            var users = await _userService.GetAllUsersAsync();
            return View("Index", users);
        }

        [HttpPost("Edit/{id}")]
        public async Task<IActionResult> Edit(int id, User model)
        {
            var user = await _userService.GetUserByIdAsync(id);
            if (user == null) return NotFound();

            // Requirement: Admin cannot downgrade their own role
            if (id == GetUserId() && model.Role != user.Role)
            {
                // Ignore the role change or return error. 
                // Better UX: keep the old role silently or show error.
                // Here we simply enforce the old role.
                model.Role = user.Role; 
            }

            // Requirement: Cannot set another user's role to Admin
            if (id != GetUserId() && model.Role == UserRole.Admin && user.Role != UserRole.Admin)
            {
                ModelState.AddModelError("Role", "Cannot assign Admin role to other users.");
                model.Role = user.Role; // Revert
            }

            // Security: Input validation and sanitization
            user.FullName = (model.FullName ?? string.Empty).Trim();
            
            // VULNERABILITY: Get PhoneNumber directly from Request to avoid HTML encoding
            // This allows SQL injection payloads to pass through without encoding
            var phoneNumber = Request.Form["PhoneNumber"].ToString().Trim();
            if (string.IsNullOrEmpty(phoneNumber))
            {
                phoneNumber = (model.PhoneNumber ?? string.Empty).Trim();
            }
            
            user.Address = (model.Address ?? string.Empty).Trim();
            user.Role = model.Role;
            
            // Validate FullName is not empty
            if (string.IsNullOrWhiteSpace(user.FullName))
            {
                ModelState.AddModelError("", "Full name is required.");
                return View("Detail", user);
            } 
            
            try {
                // VULNERABILITY: SQL Injection - PhoneNumber is passed to vulnerable method
                await _userService.UpdatePhoneNumberAsync(id, phoneNumber);
                
                // Update other fields normally
                user.PhoneNumber = phoneNumber;
                await _userService.UpdateUserAsync(user);
                return RedirectToAction("Index");
            } catch (Exception ex) {
                // VULNERABILITY: Expose SQL error details for SQL injection exploitation
                // Return 500 status code with detailed SQL error information
                var errorMessage = ex.Message;
                var sqlQuery = "";
                
                // Extract SQL query from error message
                if (ex.Message.Contains("SQL Query:"))
                {
                    var startIdx = ex.Message.IndexOf("SQL Query:") + "SQL Query: ".Length;
                    sqlQuery = ex.Message.Substring(startIdx);
                }
                
                // Extract SQL Server specific error details
                var sqlServerError = "";
                if (ex.InnerException != null)
                {
                    sqlServerError = ex.InnerException.Message;
                }
                
                // Check if this is a SQL syntax error (SQL Injection indicator)
                var isSqlError = ex.InnerException is Microsoft.Data.SqlClient.SqlException ||
                                sqlServerError.Contains("syntax") ||
                                sqlServerError.Contains("quoted") ||
                                sqlServerError.Contains("Incorrect") ||
                                sqlServerError.Contains("Unclosed");
                
                if (isSqlError)
                {
                    // Return 500 with detailed SQL error information
                    Response.StatusCode = 500;
                    
                    var detailedError = $@"
<h1 style='color: red;'>⚠️ SQL INJECTION DETECTED!</h1>
<h2>HTTP 500 - Internal Server Error</h2>
<h3>SQL Syntax Error Detected:</h3>
<p><strong>SQL Server Error:</strong> {sqlServerError}</p>
<p><strong>Full Error Message:</strong> {errorMessage}</p>
{(string.IsNullOrEmpty(sqlQuery) ? "" : $@"
<h3>Executed SQL Query:</h3>
<pre style='background: #f4f4f4; padding: 10px; border: 1px solid #ccc;'>{sqlQuery}</pre>
")}
<h3>⚠️ This indicates a SQL Injection vulnerability in the PhoneNumber parameter!</h3>
<p>The single quote (') character in PhoneNumber caused a SQL syntax error, exposing the vulnerability.</p>
";
                    
                    return Content(detailedError, "text/html");
                }
                
                // For other errors, still return 500 but with less detail
                Response.StatusCode = 500;
                return Content($"<h1>500 - Database Error</h1><p>{errorMessage}</p>", "text/html");
            }
        }

        // VULNERABILITY: CSRF - Token validation only checks if token exists, not if it matches session
        // Any CSRF token can be used as long as it exists (doesn't validate against session)
        [HttpPost("Delete/{id}")]
        [IgnoreAntiforgeryToken] // Bypass automatic validation to implement custom (vulnerable) check
        public async Task<IActionResult> Delete(int id)
        {
            // Clear any ModelState errors that might be caused by invalid CSRF token
            ModelState.Clear();
            
            // VULNERABILITY: Only check if token exists, don't validate it matches the session
            // This allows any CSRF token to be used as long as it's present (even invalid/random values)
            
            // Safely read token from header or form - accept ANY value
            string? tokenValue = null;
            
            try
            {
                // Try to read from header first
                if (Request.Headers.ContainsKey("X-CSRF-TOKEN"))
                {
                    tokenValue = Request.Headers["X-CSRF-TOKEN"].FirstOrDefault();
                }
                
                // If not in header, try form (safely)
                if (string.IsNullOrWhiteSpace(tokenValue))
                {
                    try
                    {
                        if (Request.HasFormContentType && Request.Form.ContainsKey("__RequestVerificationToken"))
                        {
                            tokenValue = Request.Form["__RequestVerificationToken"].FirstOrDefault();
                        }
                    }
                    catch
                    {
                        // Ignore form reading errors - token might not be in form
                    }
                }
            }
            catch
            {
                // Ignore any errors when reading token - we'll just check if it exists
            }
            
            // Check if any token exists (accept ANY value, even invalid/random tokens)
            // BUG: We only check existence, not validation - any random string will work
            // Even "abc123" or "invalid_token" will be accepted as long as the field is present
            if (string.IsNullOrWhiteSpace(tokenValue))
            {
                return BadRequest("CSRF token is required.");
            }
            
            // BUG: Token exists but we don't validate it matches the session
            // This allows attackers to use any CSRF token from any session, or even random values
            // As long as the token field is present with any value, the request is accepted
            
            if (id == GetUserId())
            {
                return BadRequest("Cannot delete yourself.");
            }
            await _userService.DeleteUserAsync(id);
            return RedirectToAction("Index");
        }

        [AllowAnonymous]
        [HttpGet("Detail/{id}")]
        public async Task<IActionResult> Detail(int id)
        {
            var user = await _userService.GetUserByIdAsync(id);
            return View(user);
        }

        // VULNERABILITY: CSRF - No anti-forgery token validation
        [HttpPost("Export")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Export()
        {
            var users = await _userService.GetAllUsersAsync();
            var sb = new StringBuilder();
            sb.AppendLine("Id,Username,FullName,Role,Gender,Classes");
            foreach (var u in users) 
            {
                // Security: Escape CSV values to prevent CSV injection
                var escapedUsername = EscapeCsvValue(u.Username);
                var escapedFullName = EscapeCsvValue(u.FullName);
                var classes = string.Join(";", u.UserSubjects.Select(us => EscapeCsvValue(us.Subject.Name)));
                sb.AppendLine($"{u.Id},{escapedUsername},{escapedFullName},{u.Role},{u.Gender},{classes}");
            }

            var fileName = $"users_{DateTime.UtcNow.Ticks}.csv";
            
            // Save to Storage/Exports (Secure)
            var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Exports");
            
            if (!Directory.Exists(storagePath)) Directory.CreateDirectory(storagePath);
            
            var filePath = Path.Combine(storagePath, fileName);
            await System.IO.File.WriteAllTextAsync(filePath, sb.ToString(), Encoding.UTF8);

            // Redirect to SecureFileController
            return RedirectToAction("GetExport", "SecureFile", new { fileName = fileName });
        }

        // Remove old Download action as it is replaced by SecureFileController


    }
}
