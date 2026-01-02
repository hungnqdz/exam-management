using ExamManagement.Models;

namespace ExamManagement.Services
{
    public interface IExamService
    {
        Task<List<Exam>> GetExamsBySubjectAsync(int subjectId);
        Task<List<Exam>> GetExamsForStudentAsync(int studentId); // Based on student's subjects
        Task<List<Exam>> GetExamsForTeacherAsync(int teacherId); // Based on teacher's subjects
        Task<Exam?> GetExamByIdAsync(int id);
        Task AddExamAsync(Exam exam);
        Task UpdateExamAsync(Exam exam);
        Task DeleteExamAsync(int id);
        
        // Submission
        Task SubmitExamAsync(int examId, int studentId, string filePath);
        Task<List<Submission>> GetSubmissionsForExamAsync(int examId);
        Task GradeSubmissionAsync(int submissionId, double score, int teacherId);
        Task<Submission?> GetStudentSubmissionAsync(int examId, int studentId);
    }
}
