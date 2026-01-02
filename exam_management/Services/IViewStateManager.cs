namespace ExamManagement.Services
{
    // Requirement: Support ViewState later but not implemented yet.
    // This interface serves as a placeholder for future ViewState management implementation
    // compatible with SSR/WebForms migration patterns or complex state retention.
    public interface IViewStateManager
    {
        void SaveState(string key, object value);
        object GetState(string key);
    }

    public class ViewStateManager : IViewStateManager
    {
        public object GetState(string key)
        {
            throw new NotImplementedException();
        }

        public void SaveState(string key, object value)
        {
            throw new NotImplementedException();
        }
    }
}
