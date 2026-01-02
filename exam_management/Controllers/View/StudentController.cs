using ExamManagement.Models;
using ExamManagement.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ExamManagement.Controllers.View
{
    [Authorize(Roles = "Student")]
    [Route("Student")]
    public class StudentController : Controller
    {
        private readonly IExamService _examService;
        private readonly IWebHostEnvironment _env;

        public StudentController(IExamService examService, IWebHostEnvironment env)
        {
            _examService = examService;
            _env = env;
        }

        private int GetUserId() => int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);

        [HttpGet("")]
        public async Task<IActionResult> Index()
        {
            var exams = await _examService.GetExamsForStudentAsync(GetUserId());
            return View(exams);
        }

        [HttpGet("Exam/{id}")]
        public async Task<IActionResult> ExamDetail(int id)
        {
            var exam = await _examService.GetExamByIdAsync(id);
            if (exam == null) return NotFound();

            var submission = await _examService.GetStudentSubmissionAsync(id, GetUserId());
            ViewBag.Submission = submission;

            return View(exam);
        }

        [HttpPost("Exam/Submit")]
        public async Task<IActionResult> SubmitExam(int examId, IFormFile pdfFile)
        {
            var userId = GetUserId();
            
            // Requirement: Check if already submitted
            var existing = await _examService.GetStudentSubmissionAsync(examId, userId);
            if (existing != null)
            {
                // Already submitted, do not allow resubmission
                TempData["Error"] = "You have already submitted this exam and cannot resubmit.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            if (pdfFile != null && pdfFile.Length > 0 && Path.GetExtension(pdfFile.FileName).ToLower() == ".pdf")
            {
                var fileName = $"exam_{examId}_student_{userId}_{Guid.NewGuid()}.pdf";
                
                // Save to Storage/Submissions (Secure)
                var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Submissions");
                
                if (!Directory.Exists(storagePath)) Directory.CreateDirectory(storagePath);

                using (var stream = new FileStream(Path.Combine(storagePath, fileName), FileMode.Create))
                {
                    await pdfFile.CopyToAsync(stream);
                }

                // URL points to SecureFileController
                await _examService.SubmitExamAsync(examId, userId, $"/SecureFile/Submission/{fileName}");
                TempData["Message"] = "Exam submitted successfully.";
            }
            else
            {
                TempData["Error"] = "Please upload a valid PDF file.";
            }

            return RedirectToAction("ExamDetail", new { id = examId });
        }
    }
}