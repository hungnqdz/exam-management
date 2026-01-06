using ExamManagement.Models;

namespace ExamManagement.Services
{
    public interface IAuthService
    {
        string HashPassword(string password);
        bool VerifyPassword(string password, string hash);
        string GenerateJwtToken(User user);
        Task<User?> AuthenticateAsync(string username, string password);
        Task<User> RegisterStudentAsync(string username, string password, string fullname, Gender gender, List<int> subjectIds, UserRole? role = null);
    }
}
