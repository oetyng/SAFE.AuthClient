using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SafeApp;

namespace SAFE.AuthClient
{
    public class MockAuthClient
    {
        readonly Random Random = new Random();

        public async Task<Session> CreateAppAsync()
        {
            var client = await CreateClientAsync();
            return await client.CreateAppSessionAsync(CreateAuthRequest());
        }

        public async Task<AuthClient> CreateClientAsync()
        {
            string locator = GetRandomString(10);
            string secret = GetRandomString(10);
            string invitation = GetRandomString(5);
            var credentials = new Credentials(locator, secret);
            var config = new AuthSessionConfig(credentials, keepAlive: true, invitation);
            var client = await AuthClient.InitSessionAsync(config);
            return client;
        }

        SafeApp.Utilities.AuthReq CreateAuthRequest()
        {
            var authReq = new SafeApp.Utilities.AuthReq
            {
                App = new SafeApp.Utilities.AppExchangeInfo
                { Id = GetRandomString(10), Name = GetRandomString(5), Scope = null, Vendor = GetRandomString(5) },
                AppContainer = true,
                Containers = new List<SafeApp.Utilities.ContainerPermissions>()
            };
            return authReq;
        }

        string GetRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[Random.Next(s.Length)]).ToArray());
        }
    }
}