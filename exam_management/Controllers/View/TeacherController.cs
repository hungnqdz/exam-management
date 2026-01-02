using ExamManagement.Models;
using ExamManagement.Services;
using ExamManagement.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ExamManagement.Controllers.View
{
    [Authorize(Roles = "Teacher")]
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
        public async Task<IActionResult> Students(string search)
        {
            var myStudents = await _userService.GetStudentsByTeacherClassAsync(GetUserId());
            if (!string.IsNullOrEmpty(search))
            {
                // Case-insensitive search
                search = search.ToLower();
                myStudents = myStudents.Where(s => s.Username.ToLower().Contains(search) || s.FullName.ToLower().Contains(search)).ToList();
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
            var teacherId = GetUserId();
            var teacher = await _userService.GetUserByIdAsync(teacherId);
            ViewBag.Subjects = teacher?.UserSubjects.Select(us => us.Subject).ToList() ?? new List<Subject>();
            
            var myStudents = await _userService.GetStudentsByTeacherClassAsync(GetUserId());
            return View("Students", myStudents);
        }

        [HttpPost("Students/Edit/{id}")]
        public async Task<IActionResult> EditStudent(int id, User model)
        {
             // Basic edit for teacher: Name, Phone, Address
             // Should also verify ownership again
             var user = await _userService.GetUserByIdAsync(id);
             if (user == null || user.Role != UserRole.Student) return NotFound();

             user.FullName = model.FullName;
             user.PhoneNumber = model.PhoneNumber;
             user.Address = model.Address;
             
             try {
                 await _userService.UpdateUserAsync(user);
                 return RedirectToAction("Students");
             } catch (Exception ex) {
                 ModelState.AddModelError("", ex.Message);
                 var myStudents = await _userService.GetStudentsByTeacherClassAsync(GetUserId());
                 // We might need to reload subjects if the view uses them, but EditStudent doesn't use subjects in the modal logic (it uses data attributes).
                 // However, the Create modal on the same page DOES need subjects.
                 var teacherId = GetUserId();
                 var teacher = await _userService.GetUserByIdAsync(teacherId);
                 ViewBag.Subjects = teacher?.UserSubjects.Select(us => us.Subject).ToList() ?? new List<Subject>();
                 
                 return View("Students", myStudents);
             }
        }

        [HttpPost("Students/Delete/{id}")]
        public async Task<IActionResult> DeleteStudent(int id)
        {
             var user = await _userService.GetUserByIdAsync(id);
             if (user != null && user.Role == UserRole.Student)
             {
                 await _userService.DeleteUserAsync(id);
             }
             return RedirectToAction("Students");
        }


        // --- Exam Management ---
        [HttpGet("Exams")]
        public async Task<IActionResult> Exams()
        {
            var exams = await _examService.GetExamsForTeacherAsync(GetUserId());
            return View(exams);
        }

        [HttpGet("Exams/Create")]
        public IActionResult CreateExam()
        {
            // No need to load subjects anymore as we infer it
            return View();
        }

        [HttpPost("Exams/Create")]
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
        public async Task<IActionResult> ExamDetail(int id)
        {
            var exam = await _examService.GetExamByIdAsync(id);
            if (exam == null) return NotFound();
            
            var submissions = await _examService.GetSubmissionsForExamAsync(id);
            ViewBag.Submissions = submissions;
            return View(exam);
        }

        [HttpPost("Exams/Grade")]
        public async Task<IActionResult> Grade(int submissionId, double score, int examId)
        {
            await _examService.GradeSubmissionAsync(submissionId, score, GetUserId());
            return RedirectToAction("ExamDetail", new { id = examId });
        }
    }
}
