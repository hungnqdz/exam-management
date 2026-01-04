using ExamManagement.Data;
using ExamManagement.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace ExamManagement.Controllers.View
{
    [Authorize]
    [Route("SecureFile")]
    public class SecureFileController : Controller
    {
        private readonly IWebHostEnvironment _env;
        private readonly AppDbContext _context;

        public SecureFileController(IWebHostEnvironment env, AppDbContext context)
        {
            _env = env;
            _context = context;
        }

        private int GetUserId() => int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        
        private string GetContentType(string fileName)
        {
            var provider = new FileExtensionContentTypeProvider();
            if (!provider.TryGetContentType(fileName, out var contentType))
            {
                contentType = "application/octet-stream";
            }
            return contentType;
        }

        private IActionResult ServeFile(string folder, string fileName)
        {
            // Security: Sanitize fileName to prevent path traversal attacks
            if (string.IsNullOrWhiteSpace(fileName))
                return BadRequest("Invalid file name.");
            
            // Remove any path traversal attempts
            fileName = Path.GetFileName(fileName); // This removes any directory separators
            if (string.IsNullOrWhiteSpace(fileName) || fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
                return BadRequest("Invalid file name.");
            
            var storagePath = Path.Combine(_env.ContentRootPath, "Storage", folder);
            var filePath = Path.Combine(storagePath, fileName);
            
            // Additional security: Ensure the resolved path is still within the storage directory
            var resolvedPath = Path.GetFullPath(filePath);
            var resolvedStoragePath = Path.GetFullPath(storagePath);
            if (!resolvedPath.StartsWith(resolvedStoragePath, StringComparison.Ordinal))
                return BadRequest("Invalid file path.");

            if (!System.IO.File.Exists(filePath)) return NotFound("File not found.");

            return PhysicalFile(filePath, GetContentType(fileName));
        }

        [HttpGet("Avatar/{fileName}")]
        public IActionResult GetAvatar(string fileName)
        {
            // Requirement: Must be authenticated (Covered by [Authorize] on Class)
            return ServeFile("Avatars", fileName);
        }

        [HttpGet("Submission/{fileName}")]
        public async Task<IActionResult> GetSubmission(string fileName)
        {
            // Security: Sanitize fileName first
            if (string.IsNullOrWhiteSpace(fileName))
                return BadRequest("Invalid file name.");
            
            fileName = Path.GetFileName(fileName); // Remove path traversal attempts
            
            // 1. Find the submission record.
            var submission = await _context.Submissions
                .Include(s => s.Exam)
                .FirstOrDefaultAsync(s => s.FilePath.EndsWith(fileName));

            if (submission == null) return NotFound("Submission record not found.");

            var currentUserId = GetUserId();
            var isAdmin = User.IsInRole("Admin");
            var isTeacher = User.IsInRole("Teacher");
            var isOwner = submission.StudentId == currentUserId;

            bool hasAccess = isOwner || isAdmin;

            if (!hasAccess && isTeacher)
            {
                // Requirement: Teacher can view PDF if the student studies their subject.
                var examSubjectId = submission.Exam.SubjectId;
                
                var teacherTeachesSubject = await _context.UserSubjects
                    .AnyAsync(us => us.UserId == currentUserId && us.SubjectId == examSubjectId);

                if (teacherTeachesSubject)
                {
                    hasAccess = true;
                }
            }

            if (!hasAccess)
            {
                return Forbid();
            }

            return ServeFile("Submissions", fileName);
        }

        [HttpGet("Export/{fileName}")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetExport(string fileName)
        {
            // Requirement: Only Admin
            return ServeFile("Exports", fileName);
        }
    }
}