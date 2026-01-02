using ExamManagement.Models;

namespace ExamManagement.ViewModels
{
    public class RegisterVm
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public Gender Gender { get; set; }
        public List<int> SubjectIds { get; set; } = new();
    }

    public class LoginVm
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class UserProfileVm
    {
        public string FullName { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; }
        public string? Address { get; set; }
    }

    public class ChangePasswordVm
    {
        public string OldPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

    public class CreateUserVm
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public UserRole Role { get; set; }
        public List<int>? SubjectIds { get; set; } // For Teacher/Student
    }

    public class ExamDto
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public int SubjectId { get; set; }
    }

    public class GradeDto
    {
        public int SubmissionId { get; set; }
        public double Score { get; set; }
    }
}
