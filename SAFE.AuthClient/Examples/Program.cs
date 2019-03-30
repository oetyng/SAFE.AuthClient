using System.Collections.Generic;
using System.Threading.Tasks;

namespace SAFE.AuthClient.Examples
{
    class Program
    {
        static async Task Main()
        {
            var credentials = new Credentials("some string", "some other string");
            var config = new AuthSessionConfig(credentials);

            using (var client = await AuthClient.InitSessionAsync(config))
            {
                var session = await client.CreateAppSessionAsync(GetAuthReq());
                var app = new SomeApp(session);
                await app.RunAsync();
            }
        }

        static SafeApp.Utilities.AuthReq GetAuthReq()
        {
            return new SafeApp.Utilities.AuthReq
            {
                App = new SafeApp.Utilities.AppExchangeInfo
                {
                    Id = "some id",
                    Name = "some name",
                    Scope = null,
                    Vendor = "some vendor"
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

        // Implement your app logic
        public Task RunAsync()
            => Task.FromResult(0);
    }
}