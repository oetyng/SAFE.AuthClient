using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SAFE.AuthClient.Helpers;
using SAFE.AuthClient.Models;
using SAFE.AuthClient.Native;

namespace SAFE.AuthClient.Services
{
    public class AuthSessionConfig
    {
        public AuthSessionConfig(string locator, string secret, 
            bool keepAlive = true, string invitation = null)
        {
            Locator = locator;
            Secret = secret;
            KeepAlive = keepAlive;
            Invitation = invitation;
        }
        public string Locator { get; }
        public string Secret { get; }
        public bool KeepAlive { get; }
        public string Invitation { get; }
    }

    public class AuthSession : IDisposable
    {
        readonly SemaphoreSlim _reconnectSemaphore = new SemaphoreSlim(1, 1);
        AuthSessionConfig _sessionConfig;
        Authenticator _authenticator;

        public string AuthenticationReq { get; set; }

        AuthSession(AuthSessionConfig sessionConfig)
        {
            _sessionConfig = sessionConfig;
            Authenticator.Disconnected += OnNetworkDisconnected;
            Task.Run(async () => await InitLoggingAsync());
        }

        public static async Task<AuthSession> InitAuthSession(AuthSessionConfig config)
        {
            DependencyService.Register<IAuthBindings, AuthBindings>();
            DependencyService.Register<IFileOps, FileOps>();
            await Authenticator.InitLoggingAsync(null);
            var session = new AuthSession(config);
            if (config.Invitation != null)
                await session.CreateAccountAsync();
            else
                await session.LoginAsync();
            return session;
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

        public async Task<(int, int)> GetAccountInfoAsync()
        {
            var acctInfo = await _authenticator.GetAccountInfoAsync();
            return (Convert.ToInt32(acctInfo.MutationsDone),
                Convert.ToInt32(acctInfo.MutationsDone + acctInfo.MutationsAvailable));
        }

        public async Task<List<RegisteredAppModel>> GetRegisteredAppsAsync()
        {
            var appList = await _authenticator.GetRegisteredAppsAsync();
            return appList.Select(app => new RegisteredAppModel(app.AppInfo, app.Containers)).ToList();
        }

        async Task LoginAsync()
            => _authenticator = await Authenticator.LoginAsync(
                _sessionConfig.Locator,
                _sessionConfig.Secret);

        async Task CreateAccountAsync()
            => _authenticator = await Authenticator.CreateAccountAsync(
                _sessionConfig.Locator,
                _sessionConfig.Secret,
                _sessionConfig.Invitation);

        async Task CheckAndReconnect()
        {
            await _reconnectSemaphore.WaitAsync();
            try
            {
                if (_authenticator == null)
                {
                    if (_sessionConfig.KeepAlive)
                        _authenticator = await Authenticator.LoginAsync(_sessionConfig.Locator, _sessionConfig.Secret);
                }
                else if (_authenticator.IsDisconnected)
                {
                    await _authenticator.ReconnectAsync();
                    _authenticator.IsDisconnected = false;
                }
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

            if (obj == null || _authenticator == null || obj as Authenticator != _authenticator)
                return;

            Task.Run(async () =>
            {
                if (_sessionConfig.KeepAlive)
                    await CheckAndReconnect();
            });
        }

        Task InitLoggingAsync() => Authenticator.InitLoggingAsync(null);

        ~AuthSession() => FreeState();

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
            Authenticator.Disconnected -= OnNetworkDisconnected;
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
                encodedRsp = await Authenticator.EncodeUnregisteredRespAsync(uauthReq.ReqId, isGranted);
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
            var udecodeResult = await Authenticator.UnRegisteredDecodeIpcMsgAsync(encodedReq);
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