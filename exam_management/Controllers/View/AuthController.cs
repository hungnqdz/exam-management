using ExamManagement.Models;
using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace ExamManagement.Controllers.View
{
    [Route("Auth")]
    public class AuthController : Controller
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpGet("Login")]
        public IActionResult Login() => View();

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginVm model)
        {
            var user = await _authService.AuthenticateAsync(model.Username, model.Password);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }

            var token = _authService.GenerateJwtToken(user);
            
            // Allow HTTP for IP access
            Response.Cookies.Append("access_token", token, new CookieOptions { HttpOnly = true, Secure = false, SameSite = SameSiteMode.Lax, Expires = DateTime.UtcNow.AddDays(7) });

            return RedirectToAction("Index", "Home");
        }

        [HttpGet("Register")]
        public IActionResult Register()
        {
            // Pass subjects for checkboxes
            ViewBag.Subjects = new List<Subject> 
            { 
                new Subject{Id=1, Name="Math"}, 
                new Subject{Id=2, Name="Physics"},
                new Subject{Id=3, Name="Chemistry"},
                new Subject{Id=4, Name="Literature"},
                new Subject{Id=5, Name="English"} 
            };
            return View();
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterVm model)
        {
            try
            {
                await _authService.RegisterStudentAsync(model.Username, model.Password, model.FullName, model.Gender, model.SubjectIds);
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
                // Reload subjects
                ViewBag.Subjects = new List<Subject> 
                { 
                    new Subject{Id=1, Name="Math"}, 
                    new Subject{Id=2, Name="Physics"},
                    new Subject{Id=3, Name="Chemistry"},
                    new Subject{Id=4, Name="Literature"},
                    new Subject{Id=5, Name="English"} 
                };
                return View(model);
            }
        }

        [HttpPost("Logout")]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("access_token");
            return RedirectToAction("Login");
        }
    }
}
