using System.Collections.Generic;
using System.Threading.Tasks;
using SafeApp;
using SAFE.AuthClient.Native;
using SAFE.AuthClient.Helpers;

namespace SAFE.AuthClient
{
    public class AuthClient
    {
        AuthClient()
        { }

        public static async Task<AuthClient> InitiateAsync()
        {
            DependencyService.Register<IAuthBindings, AuthBindings>();
            DependencyService.Register<IFileOps, FileOps>();
            await Authenticator.InitLoggingAsync(null);
            return new AuthClient();
        }

        public async Task<(Authenticator, Session)> CreateAccountAsync(string secret, string password, string invitation, SafeApp.Utilities.AuthReq authReq)
        {
            var auth = await Authenticator.CreateAccountAsync(secret, password, invitation);
            var (_, reqMsg) = await Session.EncodeAuthReqAsync(authReq);
            var ipcReq = await auth.DecodeIpcMessageAsync(reqMsg);

            var authIpcReq = ipcReq as AuthIpcReq;
            var resMsg = await auth.EncodeAuthRespAsync(authIpcReq, true);
            var ipcResponse = await Session.DecodeIpcMessageAsync(resMsg);

            var authResponse = ipcResponse as SafeApp.Utilities.AuthIpcMsg;

            var session = await Session.AppRegisteredAsync(authReq.App.Id, authResponse.AuthGranted);
            return (auth, session);
        }

        public async Task<(Authenticator, Session)> LoginAsync(string secret, string password, SafeApp.Utilities.AuthReq authReq)
        {
            var auth = await Authenticator.LoginAsync(secret, password);
            var (_, reqMsg) = await Session.EncodeAuthReqAsync(authReq);
            var ipcReq = await auth.DecodeIpcMessageAsync(reqMsg);

            var authIpcReq = ipcReq as AuthIpcReq;
            var resMsg = await auth.EncodeAuthRespAsync(authIpcReq, true);
            var ipcResponse = await Session.DecodeIpcMessageAsync(resMsg);

            var authResponse = ipcResponse as SafeApp.Utilities.AuthIpcMsg;

            var session = await Session.AppRegisteredAsync(authReq.App.Id, authResponse.AuthGranted);
            return (auth, session);
        }
        
        public Task<string> RevokeAppAsync(Authenticator auth, string appId)
            => auth.RevokeAppAsync(appId);

        public Task<List<RegisteredApp>> GetRegisteredAppsAsync(Authenticator auth)
            => auth.GetRegisteredAppsAsync();

        public async Task<string> AuthenticateContainerRequest(Authenticator auth, string ipcMsg, bool allow)
        {
            var ipcReq = await auth.DecodeIpcMessageAsync(ipcMsg);
            var response = await auth.EncodeContainersRespAsync(ipcReq as ContainersIpcReq, allow);
            return response;
        }

        public SafeApp.Utilities.ContainersReq SetContainerPermission(SafeApp.Utilities.AuthReq authReq, string containerType)
        {
            var containerRequest = new SafeApp.Utilities.ContainersReq
            {
                App = authReq.App,
                Containers = new List<SafeApp.Utilities.ContainerPermissions>
                {
                    new SafeApp.Utilities.ContainerPermissions
                    {
                        ContName = containerType,
                        Access = new SafeApp.Utilities.PermissionSet
                            { Read = true, Insert = true, Delete = true, ManagePermissions = true, Update = true }
                    }
                }
            };
            return containerRequest;
        }
    }
}