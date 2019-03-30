using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SafeApp;
using SAFE.AuthClient.Native;

namespace SAFE.AuthClient
{
    public class MockAuthClient
    {
        readonly Random Random = new Random();

        public async Task<(Authenticator, Session)> CreateTestSessionAsync()
        {
            string secret = GetRandomString(10);
            string password = GetRandomString(10);
            string invitation = GetRandomString(5);
            return await CreateTestSessionAsync(secret, password, invitation);
        }

        public async Task<(Authenticator, Session)> CreateTestSessionAsync(string secret, string password, string invitation)
        {
            // validate mock flag is set
            var authReq = CreateAuthRequest();
            var auth = await AuthClient.InitiateAsync();
            return await auth.CreateAccountAsync(secret, password, invitation, authReq);
        }

        public SafeApp.Utilities.AuthReq CreateAuthRequest()
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