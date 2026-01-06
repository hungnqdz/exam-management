using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ExamManagement.Controllers.View
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly IUserService _userService;
        private readonly IAuthService _authService;
        private readonly IWebHostEnvironment _env;

        public HomeController(IUserService userService, IAuthService authService, IWebHostEnvironment env)
        {
            _userService = userService;
            _authService = authService;
            _env = env;
        }

        private int GetUserId() => int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);

        public IActionResult Index(string? footer)
        {
            if (string.IsNullOrEmpty(footer))
            {
                var defaultFooter = "© 2026 Exam Management System";
                return Redirect($"/Home/Index?footer={System.Net.WebUtility.UrlEncode(defaultFooter)}");
            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            var user = await _userService.GetUserByIdAsync(GetUserId());
            if (user == null) return NotFound();
            return View(user);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateProfile(ExamManagement.Models.User model)
        {
            // Security: Input validation and sanitization
            if (model == null)
            {
                TempData["Error"] = "Invalid data.";
                return RedirectToAction("Profile");
            }
            
            var user = await _userService.GetUserByIdAsync(GetUserId());
            if (user == null) return NotFound();
            
            // Security: Sanitize inputs
            user.FullName = (model.FullName ?? string.Empty).Trim();
            user.PhoneNumber = (model.PhoneNumber ?? string.Empty).Trim();
            user.Address = (model.Address ?? string.Empty).Trim();
            user.Gender = model.Gender;
            
            // Security: Validate FullName is not empty
            if (string.IsNullOrWhiteSpace(user.FullName))
            {
                TempData["Error"] = "Full name is required.";
                return RedirectToAction("Profile");
            }
            
            await _userService.UpdateUserAsync(user);
            TempData["Message"] = "Profile Updated";
            return RedirectToAction("Profile");
        }

        [HttpPost]
        public async Task<IActionResult> UploadAvatar(IFormFile avatarFile)
        {
            if (avatarFile == null || avatarFile.Length == 0)
            {
                TempData["Error"] = "Please select a file to upload.";
                return RedirectToAction("Profile");
            }

            // Security: File size limit (5MB for avatars)
            const long maxFileSize = 5 * 1024 * 1024; // 5MB
            if (avatarFile.Length > maxFileSize)
            {
                TempData["Error"] = "File size exceeds the maximum limit of 5MB.";
                return RedirectToAction("Profile");
            }

            var extension = Path.GetExtension(avatarFile.FileName).ToLower();
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg" }; 

            if (!allowedExtensions.Contains(extension))
            {
                TempData["Error"] = "Only image files (JPG, PNG, GIF, WEBP, SVG) are allowed.";
                return RedirectToAction("Profile");
            }

            var allowedMimeTypes = new[] { "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/svg+xml", "image/svg" };
            if (!allowedMimeTypes.Contains(avatarFile.ContentType.ToLower()))
            {
                TempData["Error"] = "Invalid file type. Only image files are allowed.";
                return RedirectToAction("Profile");
            }

            // Security: Sanitize filename
            var sanitizedExt = extension;
            var fileName = $"{GetUserId()}_{Guid.NewGuid()}{sanitizedExt}";
            
            // Save to Storage/Avatars (Secure)
            var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Avatars");
            
            if (!Directory.Exists(storagePath))
            {
                Directory.CreateDirectory(storagePath);
            }
            
            var filePath = Path.Combine(storagePath, fileName);
            
            // Additional security: Ensure path is within storage directory
            var resolvedPath = Path.GetFullPath(filePath);
            var resolvedStoragePath = Path.GetFullPath(storagePath);
            if (!resolvedPath.StartsWith(resolvedStoragePath, StringComparison.Ordinal))
            {
                TempData["Error"] = "Invalid file path.";
                return RedirectToAction("Profile");
            }
            
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await avatarFile.CopyToAsync(stream);
            }

            var user = await _userService.GetUserByIdAsync(GetUserId());
            // URL points to SecureFileController
            user.AvatarUrl = $"/SecureFile/Avatar/{fileName}";
            await _userService.UpdateUserAsync(user);
            TempData["Message"] = "Avatar uploaded successfully.";
            
            return RedirectToAction("Profile");
        }

        [HttpGet]
        public IActionResult ChangePassword() => View();

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordVm model)
        {
            // Security: Input validation
            if (model == null || string.IsNullOrWhiteSpace(model.OldPassword) || string.IsNullOrWhiteSpace(model.NewPassword))
            {
                ModelState.AddModelError("", "Old password and new password are required.");
                return View(model);
            }
            
            // Security: Password strength requirements
            if (model.NewPassword.Length < 6)
            {
                ModelState.AddModelError("", "New password must be at least 6 characters long.");
                return View(model);
            }
            
            var userId = GetUserId();
            var user = await _userService.GetUserByIdAsync(userId);
            if (user == null) return NotFound();
            
            if (!_authService.VerifyPassword(model.OldPassword, user.PasswordHash))
            {
                ModelState.AddModelError("", "Incorrect old password");
                return View(model);
            }

            await _userService.ChangePasswordAsync(userId, model.NewPassword);
            var successMsg = "Password changed successfully!";
            return Redirect($"/Home/ChangePassword?message={System.Net.WebUtility.UrlEncode(successMsg)}");
        }
    }
}
