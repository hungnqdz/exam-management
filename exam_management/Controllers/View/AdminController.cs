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

        [HttpGet("")]
        public async Task<IActionResult> Index(string search)
        {
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
            // Requirement: Cannot create Admin users
            if (model.Role == UserRole.Admin)
            {
                ModelState.AddModelError("Role", "Creating Admin users is not allowed.");
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

            user.FullName = model.FullName;
            user.PhoneNumber = model.PhoneNumber;
            user.Address = model.Address;
            user.Role = model.Role; 
            
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
                var classes = string.Join(";", u.UserSubjects.Select(us => us.Subject.Name));
                sb.AppendLine($"{u.Id},{u.Username},{u.FullName},{u.Role},{u.Gender},{classes}");
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
