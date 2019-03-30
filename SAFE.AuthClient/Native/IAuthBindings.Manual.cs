﻿using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SAFE.AuthClient.Native
{
    public partial interface IAuthBindings
    {
        void CreateAccount(string locator, string secret, string invitation, Action disconnnectedCb, Action<FfiResult, IntPtr, GCHandle> cb);
        void Login(string locator, string secret, Action disconnnectedCb, Action<FfiResult, IntPtr, GCHandle> cb);
        Task<IpcReq> DecodeIpcMessage(IntPtr authPtr, string uri);
        Task<IpcReq> UnRegisteredDecodeIpcMsgAsync(string msg);
    }
}