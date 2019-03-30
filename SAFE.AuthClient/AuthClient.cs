using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SAFE.AuthClient.Helpers;
using SAFE.AuthClient.Models;
using SAFE.AuthClient.Native;

namespace SAFE.AuthClient
{
    public class AuthSessionConfig
    {
        public AuthSessionConfig(Credentials credentials, 
            bool keepAlive = true, string invitation = null)
        {
            Credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
            KeepAlive = keepAlive;
            Invitation = invitation;
        }
        public Credentials Credentials { get; }
        public bool KeepAlive { get; }
        public string Invitation { get; }
    }

    public class Credentials
    {
        public Credentials(string locator, string secret)
        {
            Locator = locator ?? throw new ArgumentNullException(nameof(locator));
            Secret = secret ?? throw new ArgumentNullException(nameof(secret));
        }
        public string Locator { get; }
        public string Secret { get; }
    }

    public class AuthClient : IDisposable
    {
        readonly SemaphoreSlim _reconnectSemaphore = new SemaphoreSlim(1, 1);
        AuthSessionConfig _sessionConfig;
        AuthSession _authenticator;

        public string AuthenticationReq { get; set; }

        AuthClient(AuthSessionConfig sessionConfig, AuthSession authenticator)
        {
            _sessionConfig = sessionConfig;
            _authenticator = authenticator;
            _authenticator.Disconnected += OnNetworkDisconnected;
        }

        public static async Task<AuthClient> InitSessionAsync(AuthSessionConfig config)
        {
            var session = await AuthSession.InitAuthAsync(config);
            var client = new AuthClient(config, session);
            return client;
        }

        public async Task<SafeApp.Session> CreateAppSessionAsync(SafeApp.Utilities.AuthReq authReq)
        {
            var (_, reqMsg) = await SafeApp.Session.EncodeAuthReqAsync(authReq);
            var ipcReq = await _authenticator.DecodeIpcMessageAsync(reqMsg);

            var authIpcReq = ipcReq as AuthIpcReq;
            var resMsg = await _authenticator.EncodeAuthRespAsync(authIpcReq, true);
            var ipcResponse = await SafeApp.Session.DecodeIpcMessageAsync(resMsg);

            var authResponse = ipcResponse as SafeApp.Utilities.AuthIpcMsg;

            var session = await SafeApp.Session.AppRegisteredAsync(authReq.App.Id, authResponse.AuthGranted);
            return session;
        }

        public Task<string> RevokeAppAsync(string appId)
            => _authenticator.RevokeAppAsync(appId);

        public async Task<(ulong, ulong)> GetAccountInfoAsync()
        {
            var info = await _authenticator.GetAccountInfoAsync();
            return (info.MutationsDone, info.MutationsDone + info.MutationsAvailable);
        }

        public async Task<List<RegisteredAppModel>> GetRegisteredAppsAsync()
        {
            var appList = await _authenticator.GetRegisteredAppsAsync();
            return appList.Select(app => new RegisteredAppModel(app.AppInfo, app.Containers)).ToList();
        }

        public async Task<string> AuthenticateContainerRequest(string ipcMsg, bool allow)
        {
            var ipcReq = await _authenticator.DecodeIpcMessageAsync(ipcMsg);
            var response = await _authenticator.EncodeContainersRespAsync(ipcReq as ContainersIpcReq, allow);
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

        async Task CheckAndReconnect()
        {
            await _reconnectSemaphore.WaitAsync();
            try
            {
                await _authenticator.ReconnectAsync();
            }
            catch (FfiException ex)
            {
                var errorMessage = Utilities.GetErrorMessage(ex);
                //await Application.Current.MainPage.DisplayAlert("Error", errorMessage, "OK");
            }
            catch (Exception ex)
            {
                //await Application.Current.MainPage.DisplayAlert("Error", $"Unable to Reconnect: {ex.Message}", "OK");
                FreeState();
                //MessagingCenter.Send(this, MessengerConstants.ResetAppViews);
            }
            finally
            {
                _reconnectSemaphore.Release(1);
            }
        }

        void OnNetworkDisconnected(object obj, EventArgs args)
        {
            Debug.WriteLine("Network Observer Fired");

            Task.Run(async () =>
            {
                if (_sessionConfig.KeepAlive)
                    await CheckAndReconnect();
            });
        }

        ~AuthClient() => FreeState();

        void FreeState()
        {
            if (_authenticator != null)
            {
                _authenticator.Dispose();
                _authenticator = null;
            }
        }

        void IDisposable.Dispose()
        {
            _authenticator.Disconnected -= OnNetworkDisconnected;
            FreeState();
            _sessionConfig = null;
            GC.SuppressFinalize(this);
        }

        #region Dubious usefulness
        internal async Task HandleUrlActivationAsync(string encodedUri)
        {
            try
            {
                if (await HandleUnregisteredAppRequest(encodedUri))
                    return;

                if (_authenticator == null)
                {
                    AuthenticationReq = encodedUri;
                    if (!_sessionConfig.KeepAlive)
                    {
                        //var response = await Application.Current.MainPage.DisplayAlert(
                        //    "Login Required",
                        //    "An application is requesting access, login to authorise",
                        //    "Login",
                        //    "Cancel");
                        //if (response)
                        //{
                        //    MessagingCenter.Send(this, MessengerConstants.NavPreviousPage);
                        //}
                    }
                    return;
                }

                //if (Connectivity.NetworkAccess == NetworkAccess.Internet)
                //{
                await CheckAndReconnect();
                //}

                var encodedReq = UrlFormat.GetRequestData(encodedUri);
                var decodeResult = await _authenticator.DecodeIpcMessageAsync(encodedReq);
                var decodedType = decodeResult.GetType();
                if (decodedType == typeof(IpcReqError))
                {
                    var error = decodeResult as IpcReqError;
                    throw new FfiException(error.Code, error.Description);
                }
                else
                {
                    //MessagingCenter.Send(this, MessengerConstants.NavPreviousPage);
                    //var requestPage = new RequestDetailPage(encodedUri, decodeResult);
                    //await Application.Current.MainPage.Navigation.PushPopupAsync(requestPage);
                }
            }
            catch (FfiException ex)
            {
                var errorMessage = Utilities.GetErrorMessage(ex);
                //await Application.Current.MainPage.DisplayAlert("Authorisation Error", errorMessage, "OK");
            }
            catch (Exception ex)
            {
                //await Application.Current.MainPage.DisplayAlert("Error", ex.Message, "OK");
            }
        }

        internal async Task<string> GetEncodedResponseAsync(IpcReq req, bool isGranted)
        {
            string encodedRsp = string.Empty;
            var requestType = req.GetType();
            if (requestType == typeof(UnregisteredIpcReq))
            {
                var uauthReq = req as UnregisteredIpcReq;
                encodedRsp = await AuthSession.EncodeUnregisteredRespAsync(uauthReq.ReqId, isGranted);
            }
            else if (requestType == typeof(AuthIpcReq))
            {
                var authReq = req as AuthIpcReq;
                encodedRsp = await _authenticator.EncodeAuthRespAsync(authReq, isGranted);
            }
            else if (requestType == typeof(ContainersIpcReq))
            {
                var containerReq = req as ContainersIpcReq;
                encodedRsp = await _authenticator.EncodeContainersRespAsync(containerReq, isGranted);
            }
            else if (requestType == typeof(ShareMDataIpcReq))
            {
                var mDataShareReq = req as ShareMDataIpcReq;
                if (!isGranted)
                {
                    throw new Exception("SharedMData request denied");
                }
                encodedRsp = await _authenticator.EncodeShareMdataRespAsync(mDataShareReq, isGranted);
            }
            return encodedRsp;
        }

        async Task<bool> HandleUnregisteredAppRequest(string encodedUri)
        {
            var encodedReq = UrlFormat.GetRequestData(encodedUri);
            var udecodeResult = await AuthSession.UnRegisteredDecodeIpcMsgAsync(encodedReq);
            if (udecodeResult.GetType() == typeof(UnregisteredIpcReq))
            {
                //var requestPage = new RequestDetailPage(encodedUri, udecodeResult);
                //await Application.Current.MainPage.Navigation.PushPopupAsync(requestPage);
                return true;
            }
            return false;
        }
        #endregion Dubious usefulness
    }
}