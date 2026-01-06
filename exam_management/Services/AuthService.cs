using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ExamManagement.Data;
using ExamManagement.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using BCrypt.Net;

namespace ExamManagement.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthService(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        public string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            // Security: Use environment variable first, then configuration
            var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY")
                ?? _configuration["Jwt:Key"]
                ?? throw new InvalidOperationException("JWT Key missing.");
            var key = Encoding.ASCII.GetBytes(jwtKey);
            
            var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") 
                ?? _configuration["Jwt:Issuer"] 
                ?? "ExamManagement";
            var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") 
                ?? _configuration["Jwt:Audience"] 
                ?? "ExamManagementUsers";
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role.ToString()),
                    new Claim("FullName", user.FullName)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = jwtIssuer,
                Audience = jwtAudience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public async Task<User?> AuthenticateAsync(string username, string password)
        {
            var user = await _context.Users.Include(u => u.UserSubjects).FirstOrDefaultAsync(u => u.Username == username);
            if (user == null || !VerifyPassword(password, user.PasswordHash))
            {
                return null;
            }
            return user;
        }

        public async Task<User> RegisterStudentAsync(string username, string password, string fullname, Gender gender, List<int> subjectIds, UserRole? role = null)
        {
            if (await _context.Users.AnyAsync(u => u.Username == username))
            {
                throw new Exception("Username already exists");
            }

            var userRole = role.HasValue ? role.Value : UserRole.Student;

            var user = new User
            {
                Username = username,
                PasswordHash = HashPassword(password),
                FullName = fullname,
                Gender = gender,
                Role = userRole
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            foreach (var subjectId in subjectIds)
            {
                _context.UserSubjects.Add(new UserSubject { UserId = user.Id, SubjectId = subjectId });
            }
            await _context.SaveChangesAsync();

            return user;
        }
    }
}
