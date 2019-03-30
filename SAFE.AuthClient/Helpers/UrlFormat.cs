using System;

namespace SAFE.AuthClient.Helpers
{
    internal static class UrlFormat
    {
        public static string Format(string appId, string encodedString, bool toAuthenticator)
        {
            var scheme = toAuthenticator ? "safe-auth" : $"{appId}";
            return $"{scheme}://{appId}/{encodedString}";
        }

        public static string GetRequestData(string url)
            => new Uri(url).PathAndQuery.Replace("/", string.Empty);

        public static string GetAppId(string url)
            => new Uri(url).Host;
    }
}