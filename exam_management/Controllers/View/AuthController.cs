using ExamManagement.Models;
using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Hosting;
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
            // Security: Input validation
            if (model == null || string.IsNullOrWhiteSpace(model.Username) || string.IsNullOrWhiteSpace(model.Password))
            {
                ModelState.AddModelError("", "Username and password are required.");
                return View(model);
            }
            
            // Security: Sanitize input
            model.Username = model.Username.Trim();
            
            // Security: Limit username length to prevent DoS
            if (model.Username.Length > 50)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }
            
            var user = await _authService.AuthenticateAsync(model.Username, model.Password);
            if (user == null)
            {
                // Security: Generic error message to prevent user enumeration
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }

            var token = _authService.GenerateJwtToken(user);
            
            // Secure cookie settings - use Secure in production
            var isDevelopment = HttpContext.RequestServices.GetRequiredService<IWebHostEnvironment>().IsDevelopment();
            Response.Cookies.Append("access_token", token, new CookieOptions 
            { 
                HttpOnly = true, 
                Secure = !isDevelopment, // Secure in production
                SameSite = SameSiteMode.Strict, // Stricter SameSite policy
                Expires = DateTime.UtcNow.AddDays(7),
                Path = "/"
            });

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
            // Security: Input validation
            if (model == null)
            {
                ModelState.AddModelError("", "All fields are required.");
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
            
            // Security: Sanitize inputs
            model.Username = (model.Username ?? string.Empty).Trim();
            model.FullName = (model.FullName ?? string.Empty).Trim();
            model.Password = model.Password ?? string.Empty;
            
            // Security: Validate required fields
            if (string.IsNullOrWhiteSpace(model.Username) || string.IsNullOrWhiteSpace(model.FullName) || string.IsNullOrWhiteSpace(model.Password))
            {
                ModelState.AddModelError("", "All fields are required.");
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
            
            // Security: Password strength requirements
            if (model.Password.Length < 6)
            {
                ModelState.AddModelError("", "Password must be at least 6 characters long.");
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
            
            // Security: Username length limit
            if (model.Username.Length > 50)
            {
                ModelState.AddModelError("", "Username must be 50 characters or less.");
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
            
            try
            {
                await _authService.RegisterStudentAsync(model.Username, model.Password, model.FullName, model.Gender, model.SubjectIds ?? new List<int>());
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
