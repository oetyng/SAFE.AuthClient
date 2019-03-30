﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SAFE.AuthClient.Models;
using SAFE.AuthClient.Native;

namespace SAFE.AuthClient.Helpers
{
    internal static class Utilities
    {
        internal static ObservableRangeCollection<T> ToObservableRangeCollection<T>(this IEnumerable<T> source)
        {
            var result = new ObservableRangeCollection<T>();
            foreach (var item in source)
                result.Add(item);

            return result;
        }

        internal static string GetErrorMessage(FfiException error)
        {
            //var current = Connectivity.NetworkAccess;
            //if (current != NetworkAccess.Internet)
            //{
            //    return "No internet connection";
            //}

            switch (error.ErrorCode)
            {
                case -2000:
                    return "Could not connect to the SAFE Network";
                case -11:
                    return "Try updating your IP on invite.maidsafe.net";
                case -101:
                    return "Account does not exist";
                case -3:
                    return "Incorrect password";
                case -102:
                    return "Account already exists";
                case -116:
                    return "Invalid invitation token";
                case -117:
                    return "Invitation already claimed";
                case -206:
                    return "SharedMData request denied";
                case -113:
                    return "Insufficient account balance";
                default:
                    return error.Message;
            }
        }

        internal static string GetRandomColor(int appNameLength)
        {
            var colors = new List<string>
            {
                "#EF5350",
                "#7E57C2",
                "#29B6F6",
                "#66BB6A",
                "#FF7043",
                "#42A5F5",
                "#EC407A",
                "#AB47BC",
                "#26A69A"
            };
            return colors[appNameLength % colors.Count];
        }

        internal static string FormatContainerName(string containerName)
        {
            if (containerName.StartsWith("apps/"))
            {
                return "App's own Container";
            }

            if (containerName == "_publicNames")
            {
                return "Public Names";
            }

            return $"{containerName.Substring(1, 1).ToUpper()}{containerName.Substring(2)}";
        }

        #region Encoding Extensions

        public static string ToUtfString(this List<byte> input)
        {
            var ba = input.ToArray();
            return Encoding.UTF8.GetString(ba, 0, ba.Length);
        }

        public static List<byte> ToUtfBytes(this string input)
        {
            var byteArray = Encoding.UTF8.GetBytes(input);
            return byteArray.ToList();
        }

        public static string ToHexString(this List<byte> byteList)
        {
            var ba = byteList.ToArray();
            var hex = BitConverter.ToString(ba);
            return hex.Replace("-", string.Empty).ToLower();
        }

        public static List<byte> ToHexBytes(this string hex)
        {
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes.ToList();
        }

        public static string PrintByteArray(List<byte> bytes)
        {
            var sb = new StringBuilder("new byte[] { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }

            sb.Append("}");
            return sb.ToString();
        }

        #endregion
    }
}