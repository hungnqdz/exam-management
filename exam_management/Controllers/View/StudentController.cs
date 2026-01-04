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

            // VULNERABILITY: IDOR - Missing authorization check for subject enrollment
            // Original security check removed for training demonstration
            // Student can now access exams from any subject by changing the ID in URL
            var studentId = GetUserId();
            
            // VULNERABILITY: Removed check:
            // - Student enrollment in the subject
            // - Authorization verification
            // This allows students to view exams from subjects they are NOT enrolled in
            // Example: Student enrolled in Math can view exams from Literature by changing URL parameter

            var submission = await _examService.GetStudentSubmissionAsync(id, studentId);
            ViewBag.Submission = submission;

            return View(exam);
        }

        [HttpPost("Exam/Submit")]
        public async Task<IActionResult> SubmitExam(int examId, IFormFile pdfFile)
        {
            var userId = GetUserId();
            
            // Security: Verify student is enrolled in the subject of this exam
            var student = await _examService.GetExamsForStudentAsync(userId);
            if (!student.Any(e => e.Id == examId))
            {
                return Forbid("You can only submit exams for subjects you are enrolled in.");
            }
            
            // Requirement: Check if already submitted
            var existing = await _examService.GetStudentSubmissionAsync(examId, userId);
            if (existing != null)
            {
                // Already submitted, do not allow resubmission
                TempData["Error"] = "You have already submitted this exam and cannot resubmit.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // Security: Validate file upload
            if (pdfFile == null || pdfFile.Length == 0)
            {
                TempData["Error"] = "Please upload a valid PDF file.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // Security: File size limit (10MB)
            const long maxFileSize = 10 * 1024 * 1024; // 10MB
            if (pdfFile.Length > maxFileSize)
            {
                TempData["Error"] = "File size exceeds the maximum limit of 10MB.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // Security: Validate file extension
            var extension = Path.GetExtension(pdfFile.FileName).ToLower();
            if (extension != ".pdf")
            {
                TempData["Error"] = "Only PDF files are allowed.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // Security: Validate MIME type
            var allowedMimeTypes = new[] { "application/pdf" };
            if (!allowedMimeTypes.Contains(pdfFile.ContentType.ToLower()))
            {
                TempData["Error"] = "Invalid file type. Only PDF files are allowed.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // Security: Sanitize filename
            var sanitizedFileName = $"exam_{examId}_student_{userId}_{Guid.NewGuid()}.pdf";
            
            // Save to Storage/Submissions (Secure)
            var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Submissions");
            
            if (!Directory.Exists(storagePath)) Directory.CreateDirectory(storagePath);

            var filePath = Path.Combine(storagePath, sanitizedFileName);
            
            // Additional security: Ensure path is within storage directory
            var resolvedPath = Path.GetFullPath(filePath);
            var resolvedStoragePath = Path.GetFullPath(storagePath);
            if (!resolvedPath.StartsWith(resolvedStoragePath, StringComparison.Ordinal))
            {
                TempData["Error"] = "Invalid file path.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await pdfFile.CopyToAsync(stream);
            }

            // URL points to SecureFileController
            await _examService.SubmitExamAsync(examId, userId, $"/SecureFile/Submission/{sanitizedFileName}");
            TempData["Message"] = "Exam submitted successfully.";

            return RedirectToAction("ExamDetail", new { id = examId });
        }
    }
}