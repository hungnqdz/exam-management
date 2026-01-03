using ExamManagement.Models;
using ExamManagement.Services;

namespace ExamManagement.Data
{
    public static class DbInitializer
    {
        public static async Task Initialize(AppDbContext context, IAuthService authService)
        {
            // Ensure database is created
            context.Database.EnsureCreated();

            // Check if admin exists
            if (!context.Users.Any(u => u.Role == UserRole.Admin))
            {
                var admin = new User
                {
                    Username = "admin",
                    // Use a default password: Admin@123
                    PasswordHash = authService.HashPassword("Admin@123"), 
                    FullName = "System Administrator",
                    Role = UserRole.Admin,
                    Gender = Gender.Other,
                    Address = "Admin Address",
                    PhoneNumber = "0000000000"
                };

                context.Users.Add(admin);
                await context.SaveChangesAsync();
            }
        }
    }
}
