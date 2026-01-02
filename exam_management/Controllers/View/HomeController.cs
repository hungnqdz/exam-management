using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Linq;

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

        public IActionResult Index()
        {
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
            // Binding directly to Entity for simplicity in SSR
            var user = await _userService.GetUserByIdAsync(GetUserId());
            user.FullName = model.FullName;
            user.PhoneNumber = model.PhoneNumber;
            user.Address = model.Address;
            user.Gender = model.Gender;
            
            await _userService.UpdateUserAsync(user);
            TempData["Message"] = "Profile Updated";
            return RedirectToAction("Profile");
        }

        [HttpPost]
        public async Task<IActionResult> UploadAvatar(IFormFile avatarFile)
        {
            if (avatarFile != null && avatarFile.Length > 0)
            {
                var allowedExtensions = new[] { ".png", ".jpg" };
                var ext = Path.GetExtension(avatarFile.FileName).ToLower();

                if (!allowedExtensions.Contains(ext))
                {
                    TempData["Error"] = "Only .png and .jpg files are allowed.";
                    return RedirectToAction("Profile");
                }

                var fileName = $"{GetUserId()}_{Guid.NewGuid()}{ext}";
                
                // Save to Storage/Avatars (Secure)
                var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Avatars");
                
                if (!Directory.Exists(storagePath))
                {
                    Directory.CreateDirectory(storagePath);
                }
                
                using (var stream = new FileStream(Path.Combine(storagePath, fileName), FileMode.Create))
                {
                    await avatarFile.CopyToAsync(stream);
                }

                var user = await _userService.GetUserByIdAsync(GetUserId());
                // URL points to SecureFileController
                user.AvatarUrl = $"/SecureFile/Avatar/{fileName}";
                await _userService.UpdateUserAsync(user);
            }
            return RedirectToAction("Profile");
        }

        [HttpGet]
        public IActionResult ChangePassword() => View();

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordVm model)
        {
            var userId = GetUserId();
            var user = await _userService.GetUserByIdAsync(userId);
            
            if (!_authService.VerifyPassword(model.OldPassword, user.PasswordHash))
            {
                ModelState.AddModelError("", "Incorrect old password");
                return View(model);
            }

            await _userService.ChangePasswordAsync(userId, model.NewPassword);
            TempData["Message"] = "Password Changed";
            return RedirectToAction("Index");
        }
    }
}