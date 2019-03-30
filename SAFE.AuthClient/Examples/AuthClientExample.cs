using System.Collections.Generic;
using System.Threading.Tasks;

namespace SAFE.AuthClient.Examples
{
    class AuthClientExample
    {
        public async Task RunExample()
        {
            var credentials = new Credentials("some string", "some other string");

            await RunAppWithNewAccount(credentials, "the invitation token");
            await RunAppWithExistingAccount(credentials);
        }

        async Task RunAppWithNewAccount(Credentials credentials, string invitationToken)
        {
            var config = new AuthSessionConfig(credentials, invitation: invitationToken);
            await RunAsync(config);
        }

        async Task RunAppWithExistingAccount(Credentials credentials)
        {
            var config = new AuthSessionConfig(credentials);
            await RunAsync(config);
        }

        async Task RunAsync(AuthSessionConfig config)
        {
            using (var client = await AuthClient.InitSessionAsync(config))
            {
                // with the client, you can create various app sessions
                // so you can run multiple apps / instances with the same client login.
                var session = await client.CreateAppSessionAsync(GetAuthReq());
                var app = new SomeApp(session);
                await app.RunAsync();
            }
        }

        SafeApp.Utilities.AuthReq GetAuthReq()
        {
            return new SafeApp.Utilities.AuthReq
            {
                App = new SafeApp.Utilities.AppExchangeInfo
                {
                    Id = "your app id",
                    Name = "your app name",
                    Scope = null,
                    Vendor = "you"
                },
                AppContainer = true,
                Containers = new List<SafeApp.Utilities.ContainerPermissions>()
            };
        }
    }

    public class SomeApp
    {
        readonly SafeApp.Session _session;

        public SomeApp(SafeApp.Session session)
            => _session = session;

        // Implement your app logic here
        public Task RunAsync()
            => Task.FromResult(0);
    }
}