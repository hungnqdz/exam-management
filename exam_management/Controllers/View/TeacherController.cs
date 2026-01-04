using ExamManagement.Models;
using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ExamManagement.Controllers.View
{
    [Authorize] // VULNERABILITY: Changed from [Authorize(Roles = "Teacher")] to allow any authenticated user
    [Route("Teacher")]
    public class TeacherController : Controller
    {
        private readonly IUserService _userService;
        private readonly IExamService _examService;

        public TeacherController(IUserService userService, IExamService examService)
        {
            _userService = userService;
            _examService = examService;
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
                // Security: Sanitize search input to prevent injection
                search = search.Trim();
                // Limit search length to prevent DoS
                if (search.Length > 100)
                {
                    search = search.Substring(0, 100);
                }
                // Case-insensitive search
                var searchLower = search.ToLower();
                myStudents = myStudents.Where(s => s.Username.ToLower().Contains(searchLower) || s.FullName.ToLower().Contains(searchLower)).ToList();
            }
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

            // Requirement: Validate teacher can only assign to their subjects
            var teacherId = GetUserId();
            var teacher = await _userService.GetUserByIdAsync(teacherId);
            var teacherSubjectIds = teacher?.UserSubjects.Select(us => us.SubjectId).ToList() ?? new List<int>();

            if (model != null && model.SubjectIds != null && model.SubjectIds.Any(sid => !teacherSubjectIds.Contains(sid)))
            {
                ModelState.AddModelError("SubjectIds", "You can only assign students to your own classes.");
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

        [HttpPost("Students/Edit/{id}")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> EditStudent(int id, User model)
        {
             // Security: Verify the student belongs to teacher's classes
             var teacherId = GetUserId();
             var myStudents = await _userService.GetStudentsByTeacherClassAsync(teacherId);
             
             // Check if the student is in teacher's classes
             if (!myStudents.Any(s => s.Id == id))
             {
                 return Forbid("You can only edit students in your classes.");
             }
             
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
                 return View("Students", myStudents);
             }
             
             try {
                 await _userService.UpdateUserAsync(user);
                 return RedirectToAction("Students");
             } catch (Exception ex) {
                 ModelState.AddModelError("", ex.Message);
                 var teacher = await _userService.GetUserByIdAsync(teacherId);
                 ViewBag.Subjects = teacher?.UserSubjects.Select(us => us.Subject).ToList() ?? new List<Subject>();
                 
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


        // --- Exam Management ---
        [HttpGet("Exams")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> Exams()
        {
            var exams = await _examService.GetExamsForTeacherAsync(GetUserId());
            return View(exams);
        }

        [HttpGet("Exams/Create")]
        [Authorize(Roles = "Teacher")]
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

        [HttpGet("Exams/Detail/{id}")]
        [Authorize(Roles = "Teacher")]
        public async Task<IActionResult> ExamDetail(int id)
        {
            var exam = await _examService.GetExamByIdAsync(id);
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
            
            var submissions = await _examService.GetSubmissionsForExamAsync(id);
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
