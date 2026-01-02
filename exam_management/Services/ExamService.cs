using ExamManagement.Data;
using ExamManagement.Models;
using Microsoft.EntityFrameworkCore;

namespace ExamManagement.Services
{
    public class ExamService : IExamService
    {
        private readonly AppDbContext _context;

        public ExamService(AppDbContext context)
        {
            _context = context;
        }

        public async Task<List<Exam>> GetExamsBySubjectAsync(int subjectId)
        {
            return await _context.Exams.Where(e => e.SubjectId == subjectId).ToListAsync();
        }

        public async Task<List<Exam>> GetExamsForStudentAsync(int studentId)
        {
            var studentSubjectIds = await _context.UserSubjects
                .Where(us => us.UserId == studentId)
                .Select(us => us.SubjectId)
                .ToListAsync();

            return await _context.Exams
                .Where(e => studentSubjectIds.Contains(e.SubjectId))
                .Include(e => e.Subject)
                .ToListAsync();
        }

        public async Task<List<Exam>> GetExamsForTeacherAsync(int teacherId)
        {
            var teacherSubjectIds = await _context.UserSubjects
                .Where(us => us.UserId == teacherId)
                .Select(us => us.SubjectId)
                .ToListAsync();

            return await _context.Exams
                .Where(e => teacherSubjectIds.Contains(e.SubjectId))
                .Include(e => e.Subject)
                .ToListAsync();
        }

        public async Task<Exam?> GetExamByIdAsync(int id)
        {
            return await _context.Exams
                .Include(e => e.Subject)
                .FirstOrDefaultAsync(e => e.Id == id);
        }

        public async Task AddExamAsync(Exam exam)
        {
            _context.Exams.Add(exam);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateExamAsync(Exam exam)
        {
            _context.Exams.Update(exam);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteExamAsync(int id)
        {
            var exam = await _context.Exams.FindAsync(id);
            if (exam != null)
            {
                _context.Exams.Remove(exam);
                await _context.SaveChangesAsync();
            }
        }

        public async Task SubmitExamAsync(int examId, int studentId, string filePath)
        {
            var existing = await _context.Submissions.FirstOrDefaultAsync(s => s.ExamId == examId && s.StudentId == studentId);
            if (existing != null)
            {
                existing.FilePath = filePath;
                existing.SubmittedAt = DateTime.UtcNow;
            }
            else
            {
                _context.Submissions.Add(new Submission
                {
                    ExamId = examId,
                    StudentId = studentId,
                    FilePath = filePath
                });
            }
            await _context.SaveChangesAsync();
        }

        public async Task<List<Submission>> GetSubmissionsForExamAsync(int examId)
        {
            return await _context.Submissions
                .Where(s => s.ExamId == examId)
                .Include(s => s.Student)
                .ToListAsync();
        }

        public async Task GradeSubmissionAsync(int submissionId, double score, int teacherId)
        {
            var sub = await _context.Submissions.FindAsync(submissionId);
            if (sub != null)
            {
                sub.Score = score;
                sub.GradedByUserId = teacherId;
                await _context.SaveChangesAsync();
            }
        }

        public async Task<Submission?> GetStudentSubmissionAsync(int examId, int studentId)
        {
            return await _context.Submissions
                .FirstOrDefaultAsync(s => s.ExamId == examId && s.StudentId == studentId);
        }
    }
}
