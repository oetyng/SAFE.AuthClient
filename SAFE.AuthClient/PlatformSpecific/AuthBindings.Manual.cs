#if !NETSTANDARD1_2 || __DESKTOP__
using System;
#if __IOS__
using ObjCRuntime;
#endif
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SAFE.AuthClient.Native
{
    public partial class AuthBindings
    {
        public void CreateAccount(
            string locator,
            string secret,
            string invitation,
            Action disconnnectedCb,
            Action<FfiResult, IntPtr, GCHandle> cb)
        {
            var userData = BindingUtils.ToHandlePtr((disconnnectedCb, cb));
            CreateAccNative(locator, secret, invitation, userData, DelegateOnAuthenticatorDisconnectCb, DelegateOnAuthenticatorCreateCb);
        }

        public Task<IpcReq> DecodeIpcMessage(IntPtr authPtr, string msg)
        {
            var (task, userData) = BindingUtils.PrepareTask<IpcReq>();
            AuthDecodeIpcMsgNative(
                authPtr,
                msg,
                userData,
                DelegateOnDecodeIpcReqAuthCb,
                DelegateOnDecodeIpcReqContainersCb,
                DelegateOnDecodeIpcReqUnregisteredCb,
                DelegateOnDecodeIpcReqShareMDataCb,
                DelegateOnFfiResultIpcReqErrorCb);
            return task;
        }

        public void Login(string locator, string secret, Action disconnnectedCb, Action<FfiResult, IntPtr, GCHandle> cb)
        {
            var userData = BindingUtils.ToHandlePtr((disconnnectedCb, cb));
            LoginNative(locator, secret, userData, DelegateOnAuthenticatorDisconnectCb, DelegateOnAuthenticatorCreateCb);
        }

#if __IOS__
        [MonoPInvokeCallback(typeof(FfiResultAuthenticatorCb))]
#endif
        static void OnAuthenticatorCreateCb(IntPtr userData, IntPtr result, IntPtr app)
        {
            var (_, action) =
                BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(userData, false);

            action(Marshal.PtrToStructure<FfiResult>(result), app, GCHandle.FromIntPtr(userData));
        }

        static readonly FfiResultAuthenticatorCb DelegateOnAuthenticatorCreateCb = OnAuthenticatorCreateCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(NoneCb))]
#endif
        static void OnAuthenticatorDisconnectCb(IntPtr userData)
        {
            var (action, _) =
                BindingUtils.FromHandlePtr<(Action, Action<FfiResult, IntPtr, GCHandle>)>(userData, false);

            action();
        }

        static readonly NoneCb DelegateOnAuthenticatorDisconnectCb = OnAuthenticatorDisconnectCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntAuthReqCb))]
#endif
        static void OnDecodeIpcReqAuthCb(IntPtr userData, uint reqId, IntPtr authReq)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
            tcs.SetResult(new AuthIpcReq(reqId, new AuthReq(Marshal.PtrToStructure<AuthReqNative>(authReq))));
        }

        static readonly UIntAuthReqCb DelegateOnDecodeIpcReqAuthCb = OnDecodeIpcReqAuthCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntContainersReqCb))]
#endif
        static void OnDecodeIpcReqContainersCb(IntPtr userData, uint reqId, IntPtr authReq)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
            tcs.SetResult(new ContainersIpcReq(reqId, new ContainersReq(Marshal.PtrToStructure<ContainersReqNative>(authReq))));
        }

        static readonly UIntContainersReqCb DelegateOnDecodeIpcReqContainersCb = OnDecodeIpcReqContainersCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntShareMDataReqMetadataResponseListCb))]
#endif
        static void OnDecodeIpcReqShareMDataCb(IntPtr userData, uint reqId, IntPtr authReq, IntPtr metadataPtr, UIntPtr metadataLen)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
            var shareMdReq = new ShareMDataReq(Marshal.PtrToStructure<ShareMDataReqNative>(authReq));
            var metadataResponseList = BindingUtils.CopyToObjectList<MetadataResponse>(metadataPtr, (int)metadataLen);
            tcs.SetResult(new ShareMDataIpcReq(reqId, shareMdReq, metadataResponseList));
        }

        static readonly UIntShareMDataReqMetadataResponseListCb DelegateOnDecodeIpcReqShareMDataCb =
            OnDecodeIpcReqShareMDataCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(UIntByteListCb))]
#endif
        static void OnDecodeIpcReqUnregisteredCb(IntPtr userData, uint reqId, IntPtr extraData, UIntPtr size)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
            tcs.SetResult(new UnregisteredIpcReq(reqId, extraData, (ulong)size));
        }

        static readonly UIntByteListCb DelegateOnDecodeIpcReqUnregisteredCb = OnDecodeIpcReqUnregisteredCb;

#if __IOS__
        [MonoPInvokeCallback(typeof(FfiResultIpcReqErrorCb))]
#endif
        static void OnFfiResultIpcReqErrorCb(IntPtr userData, IntPtr result, string msg)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<IpcReq>>(userData);
            var ffiResult = Marshal.PtrToStructure<FfiResult>(result);
            tcs.SetResult(new IpcReqError(ffiResult.ErrorCode, ffiResult.Description, msg));
        }

#if __IOS__
        [MonoPInvokeCallback(typeof(IpcReqEncodeCb))]
#endif

        // ReSharper disable once UnusedMember.Local
        static void OnIpcReqEncodeCb(IntPtr userData, IntPtr result, string msg)
        {
            var tcs = BindingUtils.FromHandlePtr<TaskCompletionSource<string>>(userData);
            var ffiResult = Marshal.PtrToStructure<FfiResult>(result);
            if (ffiResult.ErrorCode != 0 && ffiResult.ErrorCode != -200)
            {
                Task.Run(() => { tcs.SetException(ffiResult.ToException()); });
                return;
            }

            Task.Run(() => { tcs.SetResult(msg); });
        }

        public Task<IpcReq> UnRegisteredDecodeIpcMsgAsync(string msg)
        {
            var (task, userData) = BindingUtils.PrepareTask<IpcReq>();
            AuthUnregisteredDecodeIpcMsgNative(msg, userData, DelegateOnDecodeIpcReqUnregisteredCb, DelegateOnFfiResultIpcReqErrorCb);
            return task;
        }

        static readonly FfiResultStringCb DelegateOnFfiResultIpcReqErrorCb = OnFfiResultIpcReqErrorCb;

        // ReSharper disable once UnusedMember.Local
        delegate void FfiResultIpcReqErrorCb(IntPtr userData, IntPtr result, string msg);

        // ReSharper disable once UnusedMember.Local
        delegate void IpcReqEncodeCb(IntPtr userData, IntPtr result, string msg);
    }
}
#endif