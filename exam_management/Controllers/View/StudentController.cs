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

            // VULNERABILITY: Unrestricted File Upload - No validation on file type
            // Original security checks removed for training demonstration
            // This allows uploading any file type, including executable files and scripts
            
            // VULNERABILITY: Removed validations:
            // - No file extension validation
            // - No MIME type validation
            // - No file content validation
            // - Files saved to wwwroot/uploads (web-accessible directory)
            // This allows uploading malicious files (.aspx, .php, .jsp, .war, .ps1, .sh, .bat, etc.)
            // and accessing them via HTTP, potentially leading to Remote Code Execution (RCE)
            
            if (pdfFile == null || pdfFile.Length == 0)
            {
                TempData["Error"] = "Please upload a file.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // VULNERABILITY: Only basic size check (no type validation)
            const long maxFileSize = 50 * 1024 * 1024; // 50MB (increased for larger payloads)
            if (pdfFile.Length > maxFileSize)
            {
                TempData["Error"] = "File size exceeds the maximum limit of 50MB.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // VULNERABILITY: Use original filename (no sanitization)
            // This preserves dangerous extensions like .cshtml
            var originalFileName = pdfFile.FileName;
            
            // VULNERABILITY: Save to wwwroot/uploads (web-accessible directory)
            // Files in wwwroot can be accessed via HTTP, allowing execution of uploaded scripts
            var uploadsPath = Path.Combine(_env.WebRootPath, "uploads");
            
            if (!Directory.Exists(uploadsPath)) Directory.CreateDirectory(uploadsPath);

            // VULNERABILITY: Use original filename without sanitization
            // This allows files with dangerous extensions to be uploaded and accessed
            var filePath = Path.Combine(uploadsPath, originalFileName);
            
            // VULNERABILITY: Basic path check only (no strong validation)
            var resolvedPath = Path.GetFullPath(filePath);
            var resolvedUploadsPath = Path.GetFullPath(uploadsPath);
            if (!resolvedPath.StartsWith(resolvedUploadsPath, StringComparison.Ordinal))
            {
                TempData["Error"] = "Invalid file path.";
                return RedirectToAction("ExamDetail", new { id = examId });
            }

            // VULNERABILITY: Save file with original name and extension
            // This allows uploading and executing malicious scripts
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await pdfFile.CopyToAsync(stream);
            }

            // VULNERABILITY: Remote Code Execution (RCE) - Execute uploaded .cshtml files
            // If uploaded file is a .cshtml file, execute it immediately
            // This allows attacker to execute arbitrary C# code on the server
            var extension = Path.GetExtension(originalFileName).ToLower();
            
            if (extension == ".cshtml")
            {
                try
                {
                    // VULNERABILITY: Execute .cshtml file immediately after upload
                    // This allows Remote Code Execution (RCE) on the server
                    // .cshtml files can contain C# code that will be executed
                    
                    // Read the .cshtml file content
                    var cshtmlContent = await System.IO.File.ReadAllTextAsync(filePath);
                    
                    // VULNERABILITY: Compile and execute .cshtml content using Razor Engine
                    // This allows execution of arbitrary C# code embedded in .cshtml
                    var result = await ExecuteCshtmlAsync(cshtmlContent, filePath);
                    
                    // VULNERABILITY: Display execution result (may contain sensitive information)
                    TempData["ScriptOutput"] = $"CSHTML file executed successfully.\nOutput:\n{result}";
                }
                catch (Exception ex)
                {
                    // VULNERABILITY: Error handling may leak information
                    TempData["ScriptError"] = $"Error executing CSHTML file: {ex.Message}\nStackTrace: {ex.StackTrace}";
                }
            }

            // VULNERABILITY: File URL is web-accessible
            // Files can be accessed via: http://localhost:5000/uploads/{originalFileName}
            var fileUrl = $"/uploads/{Uri.EscapeDataString(originalFileName)}";
            await _examService.SubmitExamAsync(examId, userId, fileUrl);
            TempData["Message"] = "Exam submitted successfully.";

            return RedirectToAction("ExamDetail", new { id = examId });
        }

        // VULNERABILITY: Execute .cshtml file - RCE
        // .cshtml files can contain C# code that will be executed on the server
        private async Task<string> ExecuteCshtmlAsync(string cshtmlContent, string filePath)
        {
            // VULNERABILITY: Execute .cshtml file using dotnet-script
            // This allows execution of arbitrary C# code embedded in .cshtml
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