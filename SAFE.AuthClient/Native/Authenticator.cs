using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using SAFE.AuthClient.Helpers;

namespace SAFE.AuthClient.Native
{
    public class Authenticator : IDisposable
    {
        static readonly IAuthBindings AuthBindings = DependencyService.Get<IAuthBindings>();

        IntPtr _authPtr;
        GCHandle _disconnectedHandle;

        public static EventHandler Disconnected;

        public bool IsDisconnected { get; set; }

        Authenticator()
        {
            IsDisconnected = false;
            _authPtr = IntPtr.Zero;
        }

        public static bool IsMockBuild() => AuthBindings.IsMockBuild();

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

        public static Task<Authenticator> LoginAsync(string locator, string secret)
        {
            return Task.Run(() =>
            {
                var authenticator = new Authenticator();
                var tcs = new TaskCompletionSource<Authenticator>();
                Action disconnect = () => { OnDisconnected(authenticator); };
                Action<FfiResult, IntPtr, GCHandle> cb = (result, ptr, disconnectHandle) =>
                {
                    if (result.ErrorCode != 0)
                    {
                        if (disconnectHandle.IsAllocated)
                            disconnectHandle.Free();

                        tcs.SetException(result.ToException());
                        return;
                    }

                    authenticator.Init(ptr, disconnectHandle);
                    tcs.SetResult(authenticator);
                };
                AuthBindings.Login(locator, secret, disconnect, cb);
                return tcs.Task;
            });
        }

        public static Task<Authenticator> CreateAccountAsync(string locator, string secret, string invitation)
        {
            return Task.Run(
                () =>
                {
                    var authenticator = new Authenticator();
                    var tcs = new TaskCompletionSource<Authenticator>();
                    Action disconnect = () => { OnDisconnected(authenticator); };
                    Action<FfiResult, IntPtr, GCHandle> cb = (result, ptr, disconnectHandle) =>
                    {
                        if (result.ErrorCode != 0)
                        {
                            if (disconnectHandle.IsAllocated)
                            {
                                disconnectHandle.Free();
                            }

                            tcs.SetException(result.ToException());
                            return;
                        }

                        authenticator.Init(ptr, disconnectHandle);
                        tcs.SetResult(authenticator);
                    };
                    AuthBindings.CreateAccount(locator, secret, invitation, disconnect, cb);
                    return tcs.Task;
                });
        }

        public static Task SetAdditionalSearchPathAsync(string newPath)
            => AuthBindings.AuthSetAdditionalSearchPathAsync(newPath);

        public static Task OutputLogPathAsync(string outputFileName)
            => AuthBindings.AuthOutputLogPathAsync(outputFileName);

        public static Task<string> EncodeUnregisteredRespAsync(uint reqId, bool allow)
            => AuthBindings.EncodeUnregisteredRespAsync(reqId, allow);

        public static Task<string> GetExeFileStemAsync() 
            => AuthBindings.AuthExeFileStemAsync();

        public Task<AccountInfo> GetAccountInfoAsync()
            => AuthBindings.AuthAccountInfoAsync(_authPtr);

        public Task<List<AppAccess>> GetAppsAccessingMutableDataAsync(byte[] name, ulong typeTag)
            => AuthBindings.AuthAppsAccessingMutableDataAsync(_authPtr, name, typeTag);

        public Task<List<RegisteredApp>> GetRegisteredAppsAsync()
            => AuthBindings.AuthRegisteredAppsAsync(_authPtr);

        public Task<List<AppExchangeInfo>> GetRevokedAppsAsync()
            => AuthBindings.AuthRevokedAppsAsync(_authPtr);

        public Task FlushAppRevocationQueueAsync()
            => AuthBindings.AuthFlushAppRevocationQueueAsync(_authPtr);

        public Task ReconnectAsync()
            => AuthBindings.AuthReconnectAsync(_authPtr);

        public Task<string> RevokeAppAsync(string appId)
            => AuthBindings.AuthRevokeAppAsync(_authPtr, appId);

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

        ~Authenticator() => FreeAuth();

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

        static void OnDisconnected(Authenticator authenticator)
        {
            authenticator.IsDisconnected = true;
            Disconnected?.Invoke(authenticator, EventArgs.Empty);
        }
    }
}