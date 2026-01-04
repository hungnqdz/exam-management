using ExamManagement.Data;
using ExamManagement.Models;
using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace ExamManagement.Controllers.View
{
    [Authorize] // VULNERABILITY: Changed from [Authorize(Roles = "Teacher")] to allow any authenticated user
    [Route("Teacher")]
    public class TeacherController : Controller
    {
        private readonly IUserService _userService;
        private readonly IExamService _examService;
        private readonly AppDbContext _context;

        public TeacherController(IUserService userService, IExamService examService, AppDbContext context)
        {
            _userService = userService;
            _examService = examService;
            _context = context;
        }

        private int GetUserId() => int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);

        // --- Student Management ---
        [HttpGet("Students")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> Students(string search)
        {
            var myStudents = await _userService.GetStudentsByTeacherClassAsync(GetUserId());
            if (!string.IsNullOrEmpty(search))
            {
                // VULNERABILITY: No sanitization - search input is directly used
                // Case-insensitive search
                var searchLower = search.ToLower();
                myStudents = myStudents.Where(s => s.Username.ToLower().Contains(searchLower) || s.FullName.ToLower().Contains(searchLower)).ToList();
            }
            // VULNERABILITY: Reflected XSS - Search term is passed directly to view without HTML encoding
            // This allows attackers to inject malicious JavaScript that will execute in the victim's browser
            // Example payload: <script>alert('XSS')</script>
            // Or: <img src=x onerror=alert('XSS')>
            ViewBag.Search = search;
            
            // Load subjects for Create Modal
            var teacherId = GetUserId();
            var user = await _userService.GetUserByIdAsync(teacherId);
            ViewBag.Subjects = user?.UserSubjects.Select(us => us.Subject).ToList() ?? new List<Subject>();

            return View(myStudents);
        }

        [HttpPost("Students/Create")]
        public async Task<IActionResult> CreateStudent(CreateUserVm model)
        {
            // Security: Input validation and sanitization
            if (model != null)
            {
                model.Username = (model.Username ?? string.Empty).Trim();
                model.FullName = (model.FullName ?? string.Empty).Trim();
                model.Password = model.Password ?? string.Empty;
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
            else if (model.Username.Length > 50)
            {
                ModelState.AddModelError("", "Username must be 50 characters or less.");
            }
            
            if (await _userService.IsUsernameTakenAsync(model.Username))
            {
                ModelState.AddModelError("Username", "Username is already taken.");
            }

            // VULNERABILITY: Parameter Manipulation
            // Removed validation that checks if teacher teaches the subject
            // Only validates that subject exists in the system, not that teacher teaches it
            // This allows teacher to create students for subjects they don't teach
            var teacherId = GetUserId();
            var teacher = await _userService.GetUserByIdAsync(teacherId);
            
            if (model != null && model.SubjectIds != null && model.SubjectIds.Any())
            {
                // Get all valid subject IDs from database
                var validSubjectIds = await _context.Subjects.Select(s => s.Id).ToListAsync();
                
                // Check if all provided subject IDs exist in the system
                var invalidSubjectIds = model.SubjectIds.Where(sid => !validSubjectIds.Contains(sid)).ToList();
                if (invalidSubjectIds.Any())
                {
                    ModelState.AddModelError("SubjectIds", $"Invalid subject IDs: {string.Join(", ", invalidSubjectIds)}. These subjects do not exist in the system.");
                }
                // No check for whether teacher actually teaches these subjects - VULNERABILITY
            }
            
            if (ModelState.IsValid)
            {
                var user = new User 
                { 
                    Username = model.Username, 
                    FullName = model.FullName, 
                    Role = UserRole.Student, // Force Role Student
                    Gender = Gender.Male // Default or add field if needed in VM
                };
                
                try 
                {
                    // Ensure subjects are selected
                    if (model.SubjectIds == null || !model.SubjectIds.Any())
                    {
                        ModelState.AddModelError("", "Please select at least one class.");
                    }
                    else
                    {
                        await _userService.CreateUserAsync(user, model.Password, model.SubjectIds);
                        return RedirectToAction("Students");
                    }
                } 
                catch(Exception ex) 
                {
                    ModelState.AddModelError("", ex.Message);
                }
            }
            
            // Reload subjects on error
            ViewBag.Subjects = teacher?.UserSubjects.Select(us => us.Subject).ToList() ?? new List<Subject>();
            
            var myStudents = await _userService.GetStudentsByTeacherClassAsync(GetUserId());
            return View("Students", myStudents);
        }

        // VULNERABILITY: IDOR (Insecure Direct Object Reference)
        // Removed validation that checks if student belongs to teacher's classes
        // This allows teacher to edit students from other subjects they don't teach
        [HttpPost("Students/Edit/{id}")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> EditStudent(int id, User model)
        {
             var teacherId = GetUserId();
             
             // VULNERABILITY: No authorization check - removed validation that verifies student belongs to teacher's classes
             // Previously checked: if (!myStudents.Any(s => s.Id == id)) return Forbid(...);
             // Now any teacher can edit any student by manipulating the id parameter in the URL
             
             // Basic edit for teacher: Name, Phone, Address
             var user = await _userService.GetUserByIdAsync(id);
             if (user == null || user.Role != UserRole.Student) return NotFound();

             // Security: Input validation and sanitization
             user.FullName = (model.FullName ?? string.Empty).Trim();
             user.PhoneNumber = (model.PhoneNumber ?? string.Empty).Trim();
             user.Address = (model.Address ?? string.Empty).Trim();
             
             // Validate FullName is not empty
             if (string.IsNullOrWhiteSpace(user.FullName))
             {
                 ModelState.AddModelError("", "Full name is required.");
                 var teacher = await _userService.GetUserByIdAsync(teacherId);
                 ViewBag.Subjects = teacher?.UserSubjects.Select(us => us.Subject).ToList() ?? new List<Subject>();
                 var myStudents = await _userService.GetStudentsByTeacherClassAsync(teacherId);
                 return View("Students", myStudents);
             }
             
             try {
                 await _userService.UpdateUserAsync(user);
                 return RedirectToAction("Students");
             } catch (Exception ex) {
                 ModelState.AddModelError("", ex.Message);
                 var teacher = await _userService.GetUserByIdAsync(teacherId);
                 ViewBag.Subjects = teacher?.UserSubjects.Select(us => us.Subject).ToList() ?? new List<Subject>();
                 var myStudents = await _userService.GetStudentsByTeacherClassAsync(teacherId);
                 
                 return View("Students", myStudents);
             }
        }

        [HttpPost("Students/Delete/{id}")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> DeleteStudent(int id)
        {
             // Security: Verify the student belongs to teacher's classes
             var teacherId = GetUserId();
             var myStudents = await _userService.GetStudentsByTeacherClassAsync(teacherId);
             
             // Check if the student is in teacher's classes
             if (!myStudents.Any(s => s.Id == id))
             {
                 return Forbid("You can only delete students in your classes.");
             }
             
             var user = await _userService.GetUserByIdAsync(id);
             if (user != null && user.Role == UserRole.Student)
             {
                 await _userService.DeleteUserAsync(id);
             }
             return RedirectToAction("Students");
        }

        // VULNERABILITY: CSRF - GET endpoint without CSRF protection
        // Attacker can create a malicious link: /Teacher/Students/Delete/{id}
        // When user clicks the link, student will be deleted without CSRF token validation
        [HttpGet("Students/Delete/{id}")]
        [Microsoft.AspNetCore.Mvc.IgnoreAntiforgeryToken]
        public async Task<IActionResult> DeleteStudentGet(int id)
        {
             // Security: Verify the student belongs to teacher's classes
             var teacherId = GetUserId();
             var myStudents = await _userService.GetStudentsByTeacherClassAsync(teacherId);
             
             // Check if the student is in teacher's classes
             if (!myStudents.Any(s => s.Id == id))
             {
                 return Forbid("You can only delete students in your classes.");
             }
             
             var user = await _userService.GetUserByIdAsync(id);
             if (user != null && user.Role == UserRole.Student)
             {
                 await _userService.DeleteUserAsync(id);
             }
             return RedirectToAction("Students");
        }


        // --- Exam Management ---
        [HttpGet("Exams")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> Exams()
        {
            var exams = await _examService.GetExamsForTeacherAsync(GetUserId());
            return View(exams);
        }

        [HttpGet("Exams/Create")]
        [Microsoft.AspNetCore.Authorization.AllowAnonymous]
        public IActionResult CreateExam()
        {
            // No need to load subjects anymore as we infer it
            return View();
        }

        [HttpPost("Exams/Create")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> CreateExam(Exam model)
        {
            var teacherId = GetUserId();
            var user = await _userService.GetUserByIdAsync(teacherId);
            
            // Auto-assign subject (First one found)
            var subject = user?.UserSubjects.FirstOrDefault()?.Subject;
            if (subject == null)
            {
                ModelState.AddModelError("", "You are not assigned to any subject.");
                return View(model);
            }

            model.SubjectId = subject.Id;
            model.CreatedByUserId = teacherId;
            model.CreatedBy = user!; // Ensure navigation property is set if EF doesn't handle it well, though ID is enough usually

            try 
            {
                 // Check ModelState manually since we might have removed SubjectId from form
                 // Remove SubjectId error from ModelState if present because we set it programmatically
                 if (ModelState.ContainsKey("SubjectId")) ModelState.Remove("SubjectId");
                 
                 // Also CreatedByUserId
                 if (ModelState.ContainsKey("CreatedByUserId")) ModelState.Remove("CreatedByUserId");

                 // Re-validate? Or just save.
                 if (string.IsNullOrEmpty(model.Title) || string.IsNullOrEmpty(model.Content))
                 {
                     ModelState.AddModelError("", "Title and Content are required.");
                     return View(model);
                 }

                 await _examService.AddExamAsync(model);
                 return RedirectToAction("Exams");
            }
            catch (Exception ex)
            {
                 ModelState.AddModelError("", "Error creating exam: " + ex.Message);
                 return View(model);
            }
        }

        // VULNERABILITY: SQL Injection in id parameter
        // Accepting string id instead of int to allow SQL injection payloads
        [HttpGet("Exams/Detail/{id}")]
        public async Task<IActionResult> ExamDetail(string id)
        {
            // VULNERABILITY: Directly using string id in SQL query without validation
            // Convert string to int, but if conversion fails or contains SQL, it will be vulnerable
            if (!int.TryParse(id, out int examId))
            {
                // Still pass the string to service - vulnerable to SQL injection
                // This allows SQL injection even if id is not a valid integer
                examId = 0; // Default value, but we'll use the raw string in SQL
            }
            
            // Use the raw string id in SQL query - vulnerable to SQL injection
            // Call method that accepts string directly to bypass int validation
            var examService = _examService as ExamService;
            var exam = examService != null 
                ? await examService.GetExamByIdAsyncString(id)
                : await _examService.GetExamByIdAsync(int.TryParse(id, out int parsedId) ? parsedId : 0);
            if (exam == null) return NotFound();
            
            // Security: Verify teacher has permission to view this exam
            var teacherId = GetUserId();
            var teacher = await _userService.GetUserByIdAsync(teacherId);
            if (teacher == null) return NotFound();
            
            var teacherTeachesSubject = teacher.UserSubjects.Any(us => us.SubjectId == exam.SubjectId);
            if (!teacherTeachesSubject)
            {
                return Forbid("You can only view exams for subjects you teach.");
            }
            
            // Use parsed int for submissions to avoid breaking existing functionality
            var submissions = await _examService.GetSubmissionsForExamAsync(examId);
            ViewBag.Submissions = submissions;
            return View(exam);
        }

        [HttpPost("Exams/Grade")]
        [IgnoreAntiforgeryToken] // VULNERABILITY: Disable CSRF protection for training - allows direct POST requests
        // VULNERABILITY: Missing [Authorize(Roles = "Teacher")] - allows any authenticated user to grade
        // Class-level [Authorize] only checks authentication, not role
        public async Task<IActionResult> Grade(int submissionId, double score, int examId)
        {
            // VULNERABILITY: Missing role authorization check - any authenticated user can grade
            // Original security check removed for training demonstration
            var userId = GetUserId();
            var exam = await _examService.GetExamByIdAsync(examId);
            if (exam == null) return NotFound();
            
            // VULNERABILITY: Removed check for teacher role and subject assignment
            // This allows students to grade exams (privilege escalation vulnerability)
            // Student chỉ cần thay access_token trong request là có thể chấm điểm
            
            // Only validate score range
            if (score < 0 || score > 10)
            {
                TempData["Error"] = "Score must be between 0 and 10.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }
            
            // VULNERABILITY: Any authenticated user (including students) can now grade submissions
            await _examService.GradeSubmissionAsync(submissionId, score, userId);
            return RedirectToAction("ExamDetail", new { id = examId });
        }
    }
}