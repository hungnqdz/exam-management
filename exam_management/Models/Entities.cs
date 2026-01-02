using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ExamManagement.Models
{
    public enum UserRole
    {
        Admin = 0,
        Teacher = 1,
        Student = 2
    }

    public enum Gender
    {
        Male = 0,
        Female = 1,
        Other = 2
    }

    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Username { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string FullName { get; set; } = string.Empty;

        public Gender Gender { get; set; }

        public string? AvatarUrl { get; set; }
        
        public string? PhoneNumber { get; set; }
        
        public string? Address { get; set; }

        public UserRole Role { get; set; }

        // Navigation properties
        public ICollection<UserSubject> UserSubjects { get; set; } = new List<UserSubject>();
    }

    public class Subject
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Name { get; set; } = string.Empty;
    }

    // Join table for Student-Subject (Classes)
    public class UserSubject
    {
        public int UserId { get; set; }
        public User User { get; set; } = null!;

        public int SubjectId { get; set; }
        public Subject Subject { get; set; } = null!;
    }

    public class Exam
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Title { get; set; } = string.Empty;

        [Required]
        public string Content { get; set; } = string.Empty; // Description or Question text

        public int SubjectId { get; set; }
        public Subject Subject { get; set; } = null!;

        public int CreatedByUserId { get; set; } // Teacher
        [ForeignKey("CreatedByUserId")]
        public User CreatedBy { get; set; } = null!;

        public ICollection<Submission> Submissions { get; set; } = new List<Submission>();
    }

    public class Submission
    {
        [Key]
        public int Id { get; set; }

        public int ExamId { get; set; }
        public Exam Exam { get; set; } = null!;

        public int StudentId { get; set; }
        public User Student { get; set; } = null!;

        public string FilePath { get; set; } = string.Empty; // PDF Path

        public DateTime SubmittedAt { get; set; } = DateTime.UtcNow;

        public double? Score { get; set; } // 1-10

        public int? GradedByUserId { get; set; }
        public User? GradedBy { get; set; }
    }
}
