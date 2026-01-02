using ExamManagement.Models;

namespace ExamManagement.Services
{
    public interface IUserService
    {
        Task<List<User>> GetAllUsersAsync();
        Task<User?> GetUserByIdAsync(int id);
        Task<User> CreateUserAsync(User user, string password, List<int>? subjectIds = null);
        Task UpdateUserAsync(User user);
        Task DeleteUserAsync(int id);
        Task ChangePasswordAsync(int userId, string newPassword);
        Task<List<User>> SearchUsersAsync(string term);
        
        // Teacher specific
        Task<List<User>> GetStudentsByTeacherClassAsync(int teacherId);

        // Helper
        Task<List<Subject>> GetAllSubjectsAsync();
    }
}