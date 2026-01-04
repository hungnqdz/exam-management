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
            // VULNERABILITY: XSS in SVG - Ensure SVG files are served with image/svg+xml content-type
            // This allows browser to render SVG as HTML, executing any JavaScript inside
            var extension = Path.GetExtension(fileName).ToLower();
            if (extension == ".svg")
            {
                return "image/svg+xml"; // VULNERABILITY: SVG with image/svg+xml is rendered as HTML by browser
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
        [AllowAnonymous] // VULNERABILITY: Missing Authentication - Allow unauthenticated access
        public async Task<IActionResult> GetSubmission(string fileName)
        {
            // VULNERABILITY: Missing Authentication - No authorization check
            // Original security checks removed for training demonstration
            // Unauthenticated users can now access submission files by guessing/known filenames
            
            // Security: Sanitize fileName first
            if (string.IsNullOrWhiteSpace(fileName))
                return BadRequest("Invalid file name.");
            
            fileName = Path.GetFileName(fileName); // Remove path traversal attempts
            
            // VULNERABILITY: Removed authorization checks:
            // - No authentication required (AllowAnonymous)
            // - No check for submission ownership
            // - No check for teacher role and subject assignment
            // - No check for admin role
            // This allows anyone (including unauthenticated users) to download submission files
            
            // Only check if file exists in database (optional, can be removed for more severe vulnerability)
            var submission = await _context.Submissions
                .Include(s => s.Exam)
                .FirstOrDefaultAsync(s => s.FilePath.EndsWith(fileName));

            // VULNERABILITY: Even if submission not found in DB, still try to serve file
            // This allows access to files that might not be in database
            // Comment out the check below for more severe vulnerability:
            // if (submission == null) return NotFound("Submission record not found.");

            // VULNERABILITY: No authorization check - serve file directly
            return ServeFile("Submissions", fileName);
        }

        [HttpGet("Export")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetExport([FromQuery] string fileName)
        {
            // VULNERABILITY: Path Traversal - Missing input validation and path sanitization
            // Original security checks removed for training demonstration
            // Admin can now access files outside the Exports directory using path traversal
            // Note: Using query parameter to avoid browser URL normalization issues
            // LIMITED: Only allow reading /etc/passwd, block sensitive website files
            
            if (string.IsNullOrWhiteSpace(fileName))
                return BadRequest("Invalid file name.");
            
            // VULNERABILITY: No path traversal protection
            // Removed security checks:
            // - No Path.GetFileName() to remove directory separators
            // - No check for ".." sequences
            // - No check for "/" or "\" characters
            // - No path resolution validation
            
            var basePath = _env.ContentRootPath;
            string filePath;
            string resolvedPath;
            
            // VULNERABILITY: Check if fileName contains path traversal sequences
            // If it does, allow path traversal. Otherwise, look in Storage/Exports (normal functionality)
            if (fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
            {
                // VULNERABILITY: Path traversal detected - allow reading files outside Exports directory
                // LIMITED: Block sensitive website files, only allow /etc/passwd
                
                // VULNERABILITY: Use fileName directly without sanitization
                // Path.Combine will handle ".." sequences, allowing directory traversal
                filePath = Path.Combine(basePath, fileName);
                
                // VULNERABILITY: No validation that resolved path is within intended directory
                // Path.GetFullPath resolves ".." sequences, allowing access to parent directories
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
            
            // VULNERABILITY: No check to ensure path is within Storage/Exports when path traversal is used
            // This allows reading files from anywhere on the server filesystem (limited by blacklist above)
            
            if (!System.IO.File.Exists(resolvedPath))
            {
                return NotFound($"File not found. Path: {resolvedPath}");
            }
            
            // VULNERABILITY: Serve file without path validation (limited by blacklist)
            return PhysicalFile(resolvedPath, GetContentType(fileName));
        }
    }
}