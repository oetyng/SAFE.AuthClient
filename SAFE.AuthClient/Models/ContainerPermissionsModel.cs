
namespace SAFE.AuthClient.Models
{
    public class ContainerPermissionsModel
    {
        string _containerName;

        public string ContainerName
        {
            get => _containerName.StartsWith("apps/") ? "App Container" : _containerName;
            set => _containerName = value;
        }

        public PermissionSetModel Access { get; set; }
    }
}