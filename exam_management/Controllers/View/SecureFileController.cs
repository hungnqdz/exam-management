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
            var extension = Path.GetExtension(fileName).ToLower();
            if (extension == ".svg")
            {
                return "image/svg+xml"; 
            }
            
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
        [AllowAnonymous] 
        public async Task<IActionResult> GetSubmission(string fileName)
        {
            // Security: Sanitize fileName first
            if (string.IsNullOrWhiteSpace(fileName))
                return BadRequest("Invalid file name.");
            
            fileName = Path.GetFileName(fileName); // Remove path traversal attempts
            
            var submission = await _context.Submissions
                .Include(s => s.Exam)
                .FirstOrDefaultAsync(s => s.FilePath.EndsWith(fileName));

            return ServeFile("Submissions", fileName);
        }

        [HttpGet("Export")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetExport([FromQuery] string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return BadRequest("Invalid file name.");
            
            var basePath = _env.ContentRootPath;
            string filePath;
            string resolvedPath;
            
            if (fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
            {
                filePath = Path.Combine(basePath, fileName);
                
                resolvedPath = Path.GetFullPath(filePath);
                
                // LIMITED PROTECTION: Block sensitive website files
                // Blacklist to prevent reading source code and configuration files
                var fileNameLower = resolvedPath.ToLower();
                var blockedPatterns = new[]
                {
                    "program.cs",
                    "appsettings",
                    ".cs", // Block all C# source files
                    "controllers",
                    "services",
                    "models",
                    "views",
                    "data",
                    "wwwroot",
                    "storage", // Block Storage directory files
                    ".json",
                    ".config",
                    ".xml",
                    ".csproj",
                    ".sln"
                };
                
                // Whitelist: Allow reading specific system files for demo purposes
                var allowedFiles = new[]
                {
                    "/etc/passwd",
                    "\\etc\\passwd",
                    "/etc/hosts",
                    "\\etc\\hosts",
                    "/windows/system32/drivers/etc/hosts",
                    "\\windows\\system32\\drivers\\etc\\hosts",
                    "c:\\windows\\system32\\drivers\\etc\\hosts",
                    "c:/windows/system32/drivers/etc/hosts"
                };
                
                // Check if path is in whitelist (allowed files)
                bool isAllowed = false;
                foreach (var allowedFile in allowedFiles)
                {
                    if (resolvedPath.EndsWith(allowedFile, StringComparison.OrdinalIgnoreCase) ||
                        fileNameLower.Contains(allowedFile.ToLower()))
                    {
                        isAllowed = true;
                        break;
                    }
                }
                
                // Check if path contains blocked patterns (except whitelisted files)
                if (!isAllowed)
                {
                    foreach (var pattern in blockedPatterns)
                    {
                        if (fileNameLower.Contains(pattern))
                        {
                            return Forbid($"Access denied: Sensitive files are protected. Path: {resolvedPath}");
                        }
                    }
                }
            }
            else
            {
                // Normal functionality: Look for file in Storage/Exports directory
                var exportsPath = Path.Combine(basePath, "Storage", "Exports");
                filePath = Path.Combine(exportsPath, fileName);
                resolvedPath = Path.GetFullPath(filePath);
            }
            
            if (!System.IO.File.Exists(resolvedPath))
            {
                return NotFound($"File not found. Path: {resolvedPath}");
            }
            
            return PhysicalFile(resolvedPath, GetContentType(fileName));
        }
    }
}
