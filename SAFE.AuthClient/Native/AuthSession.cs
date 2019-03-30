using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using SAFE.AuthClient.Helpers;

namespace SAFE.AuthClient.Native
{
    public class AuthSession : IDisposable
    {
        static readonly IAuthBindings AuthBindings = DependencyService.Get<IAuthBindings>();
        readonly AuthSessionConfig _config;

        IntPtr _authPtr = IntPtr.Zero;
        GCHandle _disconnectedHandle;

        public EventHandler Disconnected;

        public bool IsDisconnected { get; private set; }

        AuthSession(AuthSessionConfig config)
            => _config = config;

        public static async Task<AuthSession> InitAuthAsync(AuthSessionConfig config)
        {
            DependencyService.Register<IAuthBindings, AuthBindings>();
            DependencyService.Register<IFileOps, FileOps>();
            await InitLoggingAsync(null);
            var auth = new AuthSession(config);
            if (config.Invitation != null)
                return await auth.CreateAccountAsync();
            else
                return await auth.LoginAsync();
        }

        #region Static
        public static bool IsMockBuild() => AuthBindings.IsMockBuild();

        public static Task SetAdditionalSearchPathAsync(string newPath)
            => AuthBindings.AuthSetAdditionalSearchPathAsync(newPath);

        public static Task OutputLogPathAsync(string outputFileName)
            => AuthBindings.AuthOutputLogPathAsync(outputFileName);

        public static Task<string> EncodeUnregisteredRespAsync(uint reqId, bool allow)
            => AuthBindings.EncodeUnregisteredRespAsync(reqId, allow);

        public static Task<string> GetExeFileStemAsync()
            => AuthBindings.AuthExeFileStemAsync();

        public static async Task InitLoggingAsync(string outputFileName)
        {
            var appName = await AuthBindings.AuthExeFileStemAsync();
            var fileList = new List<(string, string)>
                { ("crust.config", $"{appName}.crust.config"), ("log.toml", "log.toml") };

            var fileOps = DependencyService.Get<IFileOps>();
            await fileOps.TransferAssetsAsync(fileList);

            Debug.WriteLine($"Assets Transferred - {appName}");
            await AuthBindings.AuthSetAdditionalSearchPathAsync(fileOps.ConfigFilesPath);
            await AuthBindings.AuthInitLoggingAsync(outputFileName);
        }
        #endregion Static

        Task<AuthSession> LoginAsync()
        {
            return Task.Run(() =>
            {
                var tcs = new TaskCompletionSource<AuthSession>();
                void cb(FfiResult result, IntPtr ptr, GCHandle disconnectHandle)
                {
                    if (result.ErrorCode != 0)
                    {
                        if (disconnectHandle.IsAllocated)
                            disconnectHandle.Free();

                        tcs.SetException(result.ToException());
                        return;
                    }

                    Init(ptr, disconnectHandle);
                    tcs.SetResult(this);
                }
                var credentials = _config.Credentials;
                AuthBindings.Login(credentials.Locator, credentials.Secret, OnDisconnected, cb);
                return tcs.Task;
            });
        }

        Task<AuthSession> CreateAccountAsync()
        {
            return Task.Run(() =>
            {
                var tcs = new TaskCompletionSource<AuthSession>();
                void cb(FfiResult result, IntPtr ptr, GCHandle disconnectHandle)
                {
                    if (result.ErrorCode != 0)
                    {
                        if (disconnectHandle.IsAllocated)
                            disconnectHandle.Free();

                        tcs.SetException(result.ToException());
                        return;
                    }

                    Init(ptr, disconnectHandle);
                    tcs.SetResult(this);
                }
                var credentials = _config.Credentials;
                AuthBindings.CreateAccount(credentials.Locator, credentials.Secret, _config.Invitation, OnDisconnected, cb);
                return tcs.Task;
            });
        }

        public async Task ReconnectAsync()
        {
            if (IsDisconnected && _config.KeepAlive)
            {
                await AuthBindings.AuthReconnectAsync(_authPtr);
                IsDisconnected = false;
            }
        }

        public Task<AccountInfo> GetAccountInfoAsync()
            => AuthBindings.AuthAccountInfoAsync(_authPtr);

        public Task<List<RegisteredApp>> GetRegisteredAppsAsync()
            => AuthBindings.AuthRegisteredAppsAsync(_authPtr);

        public Task<string> RevokeAppAsync(string appId)
            => AuthBindings.AuthRevokeAppAsync(_authPtr, appId);

        public Task<List<AppExchangeInfo>> GetRevokedAppsAsync()
            => AuthBindings.AuthRevokedAppsAsync(_authPtr);

        public Task FlushAppRevocationQueueAsync()
            => AuthBindings.AuthFlushAppRevocationQueueAsync(_authPtr);

        public Task<List<AppAccess>> GetAppsAccessingMutableDataAsync(byte[] name, ulong typeTag)
            => AuthBindings.AuthAppsAccessingMutableDataAsync(_authPtr, name, typeTag);

        public Task AuthRmRevokedAppAsync(string appId)
            => AuthBindings.AuthRmRevokedAppAsync(_authPtr, appId);

        public Task<IpcReq> DecodeIpcMessageAsync(string msg)
            => AuthBindings.DecodeIpcMessage(_authPtr, msg);

        public Task<string> EncodeAuthRespAsync(AuthIpcReq authIpcReq, bool allow)
            => AuthBindings.EncodeAuthRespAsync(_authPtr, ref authIpcReq.AuthReq, authIpcReq.ReqId, allow);

        public Task<string> EncodeContainersRespAsync(ContainersIpcReq req, bool allow)
            => AuthBindings.EncodeContainersRespAsync(_authPtr, ref req.ContainersReq, req.ReqId, allow);

        public Task<string> EncodeShareMdataRespAsync(ShareMDataIpcReq req, bool allow)
            => AuthBindings.EncodeShareMDataRespAsync(_authPtr, ref req.ShareMDataReq, req.ReqId, allow);

        public static Task<IpcReq> UnRegisteredDecodeIpcMsgAsync(string msg)
            => AuthBindings.UnRegisteredDecodeIpcMsgAsync(msg);

        public void Dispose()
        {
            FreeAuth();
            GC.SuppressFinalize(this);
        }

        ~AuthSession() => FreeAuth();

        void FreeAuth()
        {
            if (_disconnectedHandle.IsAllocated)
                _disconnectedHandle.Free();

            if (_authPtr == IntPtr.Zero)
                return;

            IsDisconnected = false;
            AuthBindings.AuthFree(_authPtr);
            _authPtr = IntPtr.Zero;
        }

        void Init(IntPtr authPtr, GCHandle disconnectedHandle)
        {
            _authPtr = authPtr;
            _disconnectedHandle = disconnectedHandle;
            IsDisconnected = false;
        }

        void OnDisconnected()
        {
            IsDisconnected = true;
            Disconnected?.Invoke(this, EventArgs.Empty);
        }
    }
}