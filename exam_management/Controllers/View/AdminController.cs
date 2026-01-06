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

        [AllowAnonymous] 
        [HttpGet("")]
        public async Task<IActionResult> Index(string search)
        {
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
                    ModelState.AddModelError("", $"Lỗi khi tạo người dùng");
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
                await _userService.UpdatePhoneNumberAsync(id, phoneNumber);
                
                // Update other fields normally
                user.PhoneNumber = phoneNumber;
                await _userService.UpdateUserAsync(user);
                return RedirectToAction("Index");
            } catch (Exception ex) {
                ModelState.AddModelError("", "Lỗi khi cập nhật người dùng");
                return View("Detail", user);
            }
        }

        [HttpPost("Delete/{id}")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Delete(int id)
        {
            ModelState.Clear();
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
                    }
                }
            }
            catch
            {
            }

            if (string.IsNullOrWhiteSpace(tokenValue))
            {
                return BadRequest("CSRF token is required.");
            }

            
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

        [HttpPost("Export")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Export()
        {
            var users = await _userService.GetAllUsersAsync();
            var sb = new StringBuilder();
            sb.AppendLine("Id,Username,FullName,Role,Gender,Classes");
            foreach (var u in users) 
            {
                var escapedUsername = EscapeCsvValue(u.Username);
                var escapedFullName = EscapeCsvValue(u.FullName);
                var classes = string.Join(";", u.UserSubjects.Select(us => EscapeCsvValue(us.Subject.Name)));
                sb.AppendLine($"{u.Id},{escapedUsername},{escapedFullName},{u.Role},{u.Gender},{classes}");
            }

            return File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv", $"users_{DateTime.Now.Ticks}.csv");
        }
    }
}