using ExamManagement.Data;
using ExamManagement.Models;
using Microsoft.EntityFrameworkCore;

namespace ExamManagement.Services
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _context;
        private readonly IAuthService _authService;

        public UserService(AppDbContext context, IAuthService authService)
        {
            _context = context;
            _authService = authService;
        }

        public async Task<List<User>> GetAllUsersAsync()
        {
            return await _context.Users.Include(u => u.UserSubjects).ThenInclude(us => us.Subject).ToListAsync();
        }

        public async Task<User?> GetUserByIdAsync(int id)
        {
            return await _context.Users.Include(u => u.UserSubjects).ThenInclude(us => us.Subject).FirstOrDefaultAsync(u => u.Id == id);
        }

        public async Task<User> CreateUserAsync(User user, string password, List<int>? subjectIds = null)
        {
            user.PasswordHash = _authService.HashPassword(password);
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            if (subjectIds != null && subjectIds.Any())
            {
                foreach (var sid in subjectIds)
                {
                    _context.UserSubjects.Add(new UserSubject { UserId = user.Id, SubjectId = sid });
                }
                await _context.SaveChangesAsync();
            }
            return user;
        }

        public async Task UpdateUserAsync(User user)
        {
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteUserAsync(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null)
            {
                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
            }
        }

        public async Task ChangePasswordAsync(int userId, string newPassword)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user != null)
            {
                user.PasswordHash = _authService.HashPassword(newPassword);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<List<User>> SearchUsersAsync(string term)
        {
            return await _context.Users
                .Where(u => u.Username.Contains(term) || u.FullName.Contains(term))
                .Include(u => u.UserSubjects).ThenInclude(us => us.Subject)
                .ToListAsync();
        }

        public async Task<bool> IsUsernameTakenAsync(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;
            
            // Case-insensitive check for username
            return await _context.Users.AnyAsync(u => u.Username.ToLower() == username.ToLower());
        }

        public async Task<List<User>> GetStudentsByTeacherClassAsync(int teacherId)
        {
            // 1. Get Teacher's subjects
            var teacherSubjectIds = await _context.UserSubjects
                .Where(us => us.UserId == teacherId)
                .Select(us => us.SubjectId)
                .ToListAsync();

            if (!teacherSubjectIds.Any()) return new List<User>();

            // 2. Get Students in those subjects
            return await _context.Users
                .Where(u => u.Role == UserRole.Student && u.UserSubjects.Any(us => teacherSubjectIds.Contains(us.SubjectId)))
                .Include(u => u.UserSubjects).ThenInclude(us => us.Subject)
                .Distinct()
                .ToListAsync();
        }

        public async Task<List<Subject>> GetAllSubjectsAsync()
        {
            return await _context.Subjects.ToListAsync();
        }

        // VULNERABILITY: SQL Injection - PhoneNumber is concatenated directly into SQL query
        public async Task UpdatePhoneNumberAsync(int userId, string phoneNumber)
        {
            // VULNERABLE: Direct string concatenation allows SQL injection
            // When phoneNumber contains single quote ('), SQL syntax error will occur
            var sql = $"UPDATE Users SET PhoneNumber = '{phoneNumber}' WHERE Id = {userId}";
            try
            {
                await _context.Database.ExecuteSqlRawAsync(sql);
            }
            catch (Microsoft.Data.SqlClient.SqlException sqlEx)
            {
                // Re-throw SQL exception with full details to expose SQL injection vulnerability
                throw new Exception($"SQL Error: {sqlEx.Message} | SQL Query: {sql}", sqlEx);
            }
            catch (Exception ex)
            {
                // Catch any other database exceptions and include SQL query in error
                throw new Exception($"Database Error: {ex.Message} | SQL Query: {sql}", ex);
            }
        }
    }
}