using System;
using System.Collections.Generic;

namespace SAFE.AuthClient.Native
{
    public abstract class IpcReq
    { }

    public class AuthIpcReq : IpcReq
    {
        public AuthReq AuthReq;
        public uint ReqId;

        public AuthIpcReq(uint reqId, AuthReq authReq)
        {
            ReqId = reqId;
            AuthReq = authReq;
        }
    }

    public class UnregisteredIpcReq : IpcReq
    {
        public List<byte> ExtraData;
        public uint ReqId;

        public UnregisteredIpcReq(uint reqId, IntPtr extraDataPtr, ulong extraDataLength)
        {
            ReqId = reqId;
            ExtraData = BindingUtils.CopyToByteList(extraDataPtr, (int)extraDataLength);
        }
    }

    public class ContainersIpcReq : IpcReq
    {
        public ContainersReq ContainersReq;
        public uint ReqId;

        public ContainersIpcReq(uint reqId, ContainersReq containersReq)
        {
            ReqId = reqId;
            ContainersReq = containersReq;
        }
    }

    public class ShareMDataIpcReq : IpcReq
    {
        public List<MetadataResponse> MetadataResponse;
        public uint ReqId;
        public ShareMDataReq ShareMDataReq;

        public ShareMDataIpcReq(uint reqId, ShareMDataReq shareMDataReq, List<MetadataResponse> metadataResponseList)
        {
            ReqId = reqId;
            ShareMDataReq = shareMDataReq;
            MetadataResponse = metadataResponseList;
        }
    }

    public class IpcReqRejected : IpcReq
    {
        public readonly string Msg;

        public IpcReqRejected(string msg) => Msg = msg;
    }

    public class IpcReqError : IpcReq
    {
        public readonly int Code;
        public readonly string Description;
        public readonly string Msg;

        public IpcReqError(int code, string description, string msg)
        {
            Code = code;
            Description = description;
            Msg = msg;
        }
    }
}