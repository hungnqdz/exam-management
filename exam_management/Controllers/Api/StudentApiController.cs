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
        /// VULNERABLE: Insecure Deserialization endpoint
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

            // VULNERABLE: Allow PDF and binary files for deserialization
            var extension = Path.GetExtension(file.FileName).ToLower();
            var allowedExtensions = new[] { ".pdf", ".bin", ".dat", ".soap" };
            if (!allowedExtensions.Contains(extension))
            {
                return BadRequest(new { error = "Only PDF, BIN, DAT, or SOAP files are allowed." });
            }

            // VULNERABLE: Allow multiple MIME types
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

            // VULNERABLE: Insecure Deserialization - If file is not PDF, try to deserialize it
            // CRITICAL VULNERABILITY: This is where the exploit happens
            // ysoserial.exe -f BinaryFormatter -g PSObject -o raw -> payload.bin -c "calc" -t
            // When this payload is uploaded, it will be deserialized and execute the command
            if (extension != ".pdf")
            {
                try
                {
                    // CRITICAL VULNERABILITY: Insecure Deserialization
                    // An attacker can craft a malicious serialized object that executes arbitrary code
                    // during deserialization (Remote Code Execution - RCE)
                    
                    // Read the file content into a byte array first to ensure we have the full stream
                    byte[] fileBytes;
                    using (var memoryStream = new MemoryStream())
                    {
                        await file.CopyToAsync(memoryStream);
                        fileBytes = memoryStream.ToArray();
                    }

                    object? deserializedObject = null;
                    bool deserializationSuccess = false;

                    // CRITICAL: Try BinaryFormatter first - MOST DANGEROUS
                    // BinaryFormatter can deserialize ANY type and execute code
                    // This is the classic Insecure Deserialization vulnerability in C#
                    // Works with ysoserial payloads: -f BinaryFormatter -g PSObject -o raw
                    try
                    {
                        using (var memoryStream = new MemoryStream(fileBytes))
                        {
                            memoryStream.Position = 0;
#pragma warning disable SYSLIB0011 // BinaryFormatter is obsolete
                            var binaryFormatter = new BinaryFormatter();
                            // CRITICAL VULNERABILITY: No type checking, no validation
                            // BinaryFormatter will deserialize ANY type specified in the binary data
                            // An attacker can serialize a malicious object that executes code in:
                            // - Constructor (called during deserialization)
                            // - Property setters (called when properties are set)
                            // - OnDeserialization callbacks (IDeserializationCallback interface)
                            // - ISerializable.GetObjectData (custom serialization)
                            // 
                            // ysoserial.exe -f BinaryFormatter -g PSObject generates payloads that
                            // exploit PowerShell's PSObject deserialization to execute arbitrary commands
                            // The command execution happens DURING deserialization, not after
                            // 
                            // Example: ysoserial.exe -f BinaryFormatter -g PSObject -o raw -c "calc" -t > payload.bin
                            // Uploading this payload.bin file will execute "calc" automatically
                            deserializedObject = binaryFormatter.Deserialize(memoryStream);
#pragma warning restore SYSLIB0011
                            deserializationSuccess = true;
                        }
                    }
                    catch (Exception bfEx)
                    {
                        // If BinaryFormatter fails, try DataContractSerializer
                        // VULNERABLE: DataContractSerializer can also be exploited
                        try
                        {
                            using (var memoryStream = new MemoryStream(fileBytes))
                            {
                                memoryStream.Position = 0;
                                var serializer = new DataContractSerializer(typeof(SubmissionMetadata));
                                // DANGEROUS: DataContractSerializer can deserialize types
                                // This allows attackers to craft malicious SubmissionMetadata objects
                                // that execute code in OnDeserialization callback
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
                                // Log but don't fail the request - makes vulnerability harder to detect
                                System.Diagnostics.Debug.WriteLine($"All deserialization attempts failed. BinaryFormatter: {bfEx.Message}, XML: {xmlEx.Message}");
                            }
                        }
                    }
                    
                    // Process the deserialized object
                    // CRITICAL: The deserialization process itself executes code
                    // Even if we don't use the object, the damage is already done
                    // For ysoserial PSObject payloads, code execution happens during deserialization
                    if (deserializedObject != null)
                    {
                        // The deserialization process has already executed any malicious code
                        // This is why Insecure Deserialization is so dangerous - code runs automatically
                        System.Diagnostics.Debug.WriteLine($"Deserialized object type: {deserializedObject.GetType().FullName}");
                        
                        if (deserializedObject is SubmissionMetadata metadata)
                        {
                            System.Diagnostics.Debug.WriteLine($"Deserialized metadata for Exam {metadata.ExamId}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Silently continue even if deserialization fails
                    // This makes the vulnerability harder to detect
                    // Note: Even if an exception is thrown, code may have already executed
                    // Some payloads execute code before throwing exceptions
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

