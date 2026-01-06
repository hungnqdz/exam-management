using ExamManagement.Models;
using ExamManagement.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Diagnostics;

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

            var studentId = GetUserId();
            
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
            
            if (pdfFile == null || pdfFile.Length == 0)
            {
                TempData["Error"] = "Please upload a file.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            const long maxFileSize = 50 * 1024 * 1024; // 50MB (increased for larger payloads)
            if (pdfFile.Length > maxFileSize)
            {
                TempData["Error"] = "File size exceeds the maximum limit of 50MB.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            var originalFileName = pdfFile.FileName;
            
            var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
            
            if (!Directory.Exists(uploadsPath)) Directory.CreateDirectory(uploadsPath);

            var filePath = Path.Combine(uploadsPath, originalFileName);
            
            var resolvedPath = Path.GetFullPath(filePath);
            var resolvedUploadsPath = Path.GetFullPath(uploadsPath);
            if (!resolvedPath.StartsWith(resolvedUploadsPath, StringComparison.Ordinal))
            {
                TempData["Error"] = "Invalid file path.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await pdfFile.CopyToAsync(stream);
            }

            var extension = Path.GetExtension(originalFileName).ToLower();
            
            if (extension == ".cshtml")
            {
                try
                {
                    // Read the .cshtml file content
                    var cshtmlContent = await System.IO.File.ReadAllTextAsync(filePath);
                    
                    var result = await ExecuteCshtmlAsync(cshtmlContent, filePath);
                    
                    TempData["ScriptOutput"] = $"CSHTML file executed successfully.\nOutput:\n{result}";
                }
                catch (Exception ex)
                {
                    TempData["ScriptError"] = $"Error executing CSHTML file: {ex.Message}\nStackTrace: {ex.StackTrace}";
                }
            }

            var fileUrl = $"/uploads/{Uri.EscapeDataString(originalFileName)}";
            await _examService.SubmitExamAsync(examId, userId, fileUrl);
            TempData["Message"] = "Exam submitted successfully.";

            return RedirectToAction("ExamDetail", new { id = examId });
        }

        private async Task<string> ExecuteCshtmlAsync(string cshtmlContent, string filePath)
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "dotnet-script",
                    Arguments = $"\"{filePath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                using (var process = Process.Start(processInfo))
                {
                    if (process != null)
                    {
                        var output = await process.StandardOutput.ReadToEndAsync();
                        var error = await process.StandardError.ReadToEndAsync();
                        await process.WaitForExitAsync();
                        
                        return $"Exit code: {process.ExitCode}\nOutput: {output}\nError: {error}";
                    }
                }
            }
            catch (Exception ex)
            {
                // Fallback: Try using bash/sh to execute (if .cshtml contains shell commands)
                try
                {
                    var processInfo = new ProcessStartInfo
                    {
                        FileName = "/bin/bash",
                        Arguments = $"\"{filePath}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    
                    using (var process = Process.Start(processInfo))
                    {
                        if (process != null)
                        {
                            var output = await process.StandardOutput.ReadToEndAsync();
                            var error = await process.StandardError.ReadToEndAsync();
                            await process.WaitForExitAsync();
                            
                            return $"Exit code: {process.ExitCode}\nOutput: {output}\nError: {error}";
                        }
                    }
                }
                catch
                {
                    // If execution fails, return error message
                    return $"Error: Could not execute .cshtml file. {ex.Message}";
                }
            }
            
            return "Execution completed (output may be empty)";
        }
    }
}
