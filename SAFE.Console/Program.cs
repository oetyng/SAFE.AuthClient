using SAFE.AuthClient.Services;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SAFE.Console
{
    class Program
    {
        static async Task Main()
        {
            var config = new AuthSessionConfig("oetyng-123", "oetyng-123");

            using (var auth = await AuthSession.InitAuthSession(config))
            {
                var app = await auth.CreateAppSessionAsync(GetAuthReq());

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