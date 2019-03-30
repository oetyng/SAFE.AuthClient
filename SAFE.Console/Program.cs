using SAFE.AuthClient;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SAFE.Console
{
    class Program
    {
        static async Task Main()
        {
            var credentials = new Credentials("oetyng-123", "oetyng-123");
            var config = new AuthSessionConfig(credentials);

            using (var client = await AuthClient.AuthClient.InitSessionAsync(config))
            {
                var app = await client.CreateAppSessionAsync(GetAuthReq());
                // run program with app
            }
        }

        static SafeApp.Utilities.AuthReq GetAuthReq()
        {
            return new SafeApp.Utilities.AuthReq
            {
                App = new SafeApp.Utilities.AppExchangeInfo
                { Id = "someid", Name = "somename", Scope = null, Vendor = "somevendor" },
                AppContainer = true,
                Containers = new List<SafeApp.Utilities.ContainerPermissions>()
            };
        }
    }
}