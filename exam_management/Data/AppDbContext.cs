using Microsoft.EntityFrameworkCore;
using ExamManagement.Models;

namespace ExamManagement.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<Subject> Subjects { get; set; }
        public DbSet<UserSubject> UserSubjects { get; set; }
        public DbSet<Exam> Exams { get; set; }
        public DbSet<Submission> Submissions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Unique Username
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique();

            // Many-to-Many: User <-> Subject
            modelBuilder.Entity<UserSubject>()
                .HasKey(us => new { us.UserId, us.SubjectId });

            modelBuilder.Entity<UserSubject>()
                .HasOne(us => us.User)
                .WithMany(u => u.UserSubjects)
                .HasForeignKey(us => us.UserId)
                .OnDelete(DeleteBehavior.Cascade); // If user is deleted, remove class association

            modelBuilder.Entity<UserSubject>()
                .HasOne(us => us.Subject)
                .WithMany()
                .HasForeignKey(us => us.SubjectId);

            // Submissions
            modelBuilder.Entity<Submission>()
                .HasOne(s => s.Student)
                .WithMany()
                .HasForeignKey(s => s.StudentId)
                .OnDelete(DeleteBehavior.Restrict); // Keep submission even if student deleted? Or Cascade? Restrict is safer for records.

            modelBuilder.Entity<Submission>()
                .HasOne(s => s.Exam)
                .WithMany(e => e.Submissions)
                .HasForeignKey(s => s.ExamId)
                .OnDelete(DeleteBehavior.Cascade);

            // Seed Subjects
            modelBuilder.Entity<Subject>().HasData(
                new Subject { Id = 1, Name = "Toán" },
                new Subject { Id = 2, Name = "Lý" },
                new Subject { Id = 3, Name = "Hoá" },
                new Subject { Id = 4, Name = "Văn" },
                new Subject { Id = 5, Name = "Anh" }
            );
            
            // Seed Admin User (Default) - Password: "admin"
            // Using a static hash for "admin" to avoid BCrypt dependency in OnModelCreating if possible, 
            // but for simplicity I will use a placeholder and users should change it.
            // Actually, I'll generate a real hash later or seed via a service. 
            // Let's just seed the subjects here.
        }
    }
}
