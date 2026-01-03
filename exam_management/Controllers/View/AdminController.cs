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

        [HttpGet("")]
        public async Task<IActionResult> Index(string search)
        {
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
        public async Task<IActionResult> Create(CreateUserVm model)
        {
            // Security: Input validation and sanitization
            if (model != null)
            {
                model.Username = (model.Username ?? string.Empty).Trim();
                model.FullName = (model.FullName ?? string.Empty).Trim();
                model.Password = model.Password ?? string.Empty;
            }
            
            // Requirement: Cannot create Admin users
            if (model != null && model.Role == UserRole.Admin)
            {
                ModelState.AddModelError("Role", "Creating Admin users is not allowed.");
            }

            // Security: Validate required fields
            if (model == null || string.IsNullOrWhiteSpace(model.Username) || string.IsNullOrWhiteSpace(model.FullName) || string.IsNullOrWhiteSpace(model.Password))
            {
                ModelState.AddModelError("", "Username, Full Name, and Password are required.");
            }
            else if (model.Password.Length < 6)
            {
                ModelState.AddModelError("", "Password must be at least 6 characters long.");
            }

            if (ModelState.IsValid)
            {
                var user = new User { Username = model.Username, FullName = model.FullName, Role = model.Role };
                try {
                    await _userService.CreateUserAsync(user, model.Password, model.SubjectIds);
                    return RedirectToAction("Index");
                } catch(Exception ex) {
                    ModelState.AddModelError("", ex.Message);
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

            // Security: Input validation and sanitization
            user.FullName = (model.FullName ?? string.Empty).Trim();
            user.PhoneNumber = (model.PhoneNumber ?? string.Empty).Trim();
            user.Address = (model.Address ?? string.Empty).Trim();
            user.Role = model.Role;
            
            // Validate FullName is not empty
            if (string.IsNullOrWhiteSpace(user.FullName))
            {
                ModelState.AddModelError("", "Full name is required.");
                return View("Detail", user);
            } 
            
            try {
                await _userService.UpdateUserAsync(user);
                return RedirectToAction("Index");
            } catch (Exception ex) {
                ModelState.AddModelError("", ex.Message);
                return View("Detail", user);
            }
        }

        [HttpPost("Delete/{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            if (id == GetUserId())
            {
                return BadRequest("Cannot delete yourself.");
            }
            await _userService.DeleteUserAsync(id);
            return RedirectToAction("Index");
        }

        [HttpGet("Detail/{id}")]
        public async Task<IActionResult> Detail(int id)
        {
            var user = await _userService.GetUserByIdAsync(id);
            return View(user);
        }

        [HttpPost("Export")]
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
