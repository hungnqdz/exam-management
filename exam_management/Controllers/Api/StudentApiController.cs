using ExamManagement.Models;
using ExamManagement.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml;

namespace ExamManagement.Controllers.Api
{
    [Authorize(Roles = "Student")]
    [ApiController]
    [Route("Student")]
    public class StudentApiController : ControllerBase
    {
        private readonly IExamService _examService;
        private readonly IWebHostEnvironment _env;

        public StudentApiController(IExamService examService, IWebHostEnvironment env)
        {
            _examService = examService;
            _env = env;
        }

        private int GetUserId() => int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);

        /// <summary>
        /// API 29. POST /Student/SubmitExam
        /// Accepts file uploads and deserializes binary files without proper validation
        /// </summary>
        [HttpPost("SubmitExam")]
        public async Task<IActionResult> SubmitExam([FromForm] int examId, [FromForm] IFormFile file)
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
                return BadRequest(new { error = "You have already submitted this exam and cannot resubmit." });
            }

            // Security: Validate file upload
            if (file == null || file.Length == 0)
            {
                return BadRequest(new { error = "Please upload a valid file." });
            }

            // Security: File size limit (10MB)
            const long maxFileSize = 10 * 1024 * 1024; // 10MB
            if (file.Length > maxFileSize)
            {
                return BadRequest(new { error = "File size exceeds the maximum limit of 10MB." });
            }

            var extension = Path.GetExtension(file.FileName).ToLower();
            var allowedExtensions = new[] { ".pdf", ".bin", ".dat", ".soap" };
            if (!allowedExtensions.Contains(extension))
            {
                return BadRequest(new { error = "Only PDF, BIN, DAT, or SOAP files are allowed." });
            }

            var allowedMimeTypes = new[] { "application/pdf", "application/octet-stream", "application/soap+xml", "application/x-binary" };
            if (!allowedMimeTypes.Contains(file.ContentType.ToLower()) && !file.ContentType.StartsWith("application/"))
            {
                return BadRequest(new { error = "Invalid file type." });
            }

            // Sanitize filename with original extension
            var sanitizedFileName = $"exam_{examId}_student_{userId}_{Guid.NewGuid()}{extension}";
            
            // Save to Storage/Submissions
            var storagePath = Path.Combine(_env.ContentRootPath, "Storage", "Submissions");
            
            if (!Directory.Exists(storagePath)) Directory.CreateDirectory(storagePath);

            var filePath = Path.Combine(storagePath, sanitizedFileName);
            
            // Additional security: Ensure path is within storage directory
            var resolvedPath = Path.GetFullPath(filePath);
            var resolvedStoragePath = Path.GetFullPath(storagePath);
            if (!resolvedPath.StartsWith(resolvedStoragePath, StringComparison.Ordinal))
            {
                return BadRequest(new { error = "Invalid file path." });
            }

            if (extension != ".pdf")
            {
                try
                {
                    
                    // Read the file content into a byte array first to ensure we have the full stream
                    byte[] fileBytes;
                    using (var memoryStream = new MemoryStream())
                    {
                        await file.CopyToAsync(memoryStream);
                        fileBytes = memoryStream.ToArray();
                    }

                    object? deserializedObject = null;
                    bool deserializationSuccess = false;

                    try
                    {
                        using (var memoryStream = new MemoryStream(fileBytes))
                        {
                            memoryStream.Position = 0;
#pragma warning disable SYSLIB0011 // BinaryFormatter is obsolete
                            var binaryFormatter = new BinaryFormatter();
                            deserializedObject = binaryFormatter.Deserialize(memoryStream);
#pragma warning restore SYSLIB0011
                            deserializationSuccess = true;
                        }
                    }
                    catch (Exception bfEx)
                    {
                        // If BinaryFormatter fails, try DataContractSerializer
                        try
                        {
                            using (var memoryStream = new MemoryStream(fileBytes))
                            {
                                memoryStream.Position = 0;
                                var serializer = new DataContractSerializer(typeof(SubmissionMetadata));
                                deserializedObject = serializer.ReadObject(memoryStream);
                                deserializationSuccess = true;
                            }
                        }
                        catch
                        {
                            // If both fail, try XML deserialization
                            try
                            {
                                using (var memoryStream = new MemoryStream(fileBytes))
                                {
                                    memoryStream.Position = 0;
                                    var xmlReader = XmlReader.Create(memoryStream);
                                    var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(SubmissionMetadata));
                                    deserializedObject = xmlSerializer.Deserialize(xmlReader);
                                    deserializationSuccess = true;
                                }
                            }
                            catch (Exception xmlEx)
                            {
                                System.Diagnostics.Debug.WriteLine($"All deserialization attempts failed. BinaryFormatter: {bfEx.Message}, XML: {xmlEx.Message}");
                            }
                        }
                    }
                    
                    if (deserializedObject != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"Deserialized object type: {deserializedObject.GetType().FullName}");
                        
                        if (deserializedObject is SubmissionMetadata metadata)
                        {
                            System.Diagnostics.Debug.WriteLine($"Deserialized metadata for Exam {metadata.ExamId}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Deserialization error: {ex.Message}");
                    System.Diagnostics.Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                }
            }

            // Save the file
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            // URL points to SecureFileController
            await _examService.SubmitExamAsync(examId, userId, $"/SecureFile/Submission/{sanitizedFileName}");

            return Ok(new 
            { 
                message = "Exam submitted successfully.",
                filePath = $"/SecureFile/Submission/{sanitizedFileName}",
                fileName = sanitizedFileName
            });
        }
    }
}