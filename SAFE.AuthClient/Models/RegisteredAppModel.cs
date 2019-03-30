﻿using System;
using System.Collections.Generic;
using System.Linq;
using SAFE.AuthClient.Helpers;
using SAFE.AuthClient.Native;

namespace SAFE.AuthClient.Models
{
    public class RegisteredAppModel : ObservableObject, IComparable, IEquatable<RegisteredAppModel>
    {
        public AppExchangeInfo AppInfo { get; }
        public string AppName => AppInfo.Name;
        public string AppVendor => AppInfo.Vendor;
        public string AppId => AppInfo.Id;
        public string CircleColor { get; set; }
        public ObservableRangeCollection<ContainerPermissionsModel> Containers { get; }

        public RegisteredAppModel(AppExchangeInfo appInfo, IEnumerable<ContainerPermissions> containers)
        {
            AppInfo = appInfo;
            Containers = containers.Select(
                x => new ContainerPermissionsModel
                {
                    Access = new PermissionSetModel
                    {
                        Read = x.Access.Read,
                        Insert = x.Access.Insert,
                        Update = x.Access.Update,
                        Delete = x.Access.Delete,
                        ManagePermissions = x.Access.ManagePermissions
                    },
                    ContainerName = Utilities.FormatContainerName(x.ContName)
                }).ToObservableRangeCollection();

            Containers = Containers.OrderBy(c => c.ContainerName).ToObservableRangeCollection();
            CircleColor = Utilities.GetRandomColor(AppName.Length);
        }

        public int CompareTo(object obj)
        {
            if (!(obj is RegisteredAppModel other))
                throw new NotSupportedException();

            return string.CompareOrdinal(AppInfo.Name, other.AppInfo.Name);
        }

        public bool Equals(RegisteredAppModel other)
        {
            if (other is null)
                return false;

            return ReferenceEquals(this, other) || AppInfo.Id.Equals(other.AppInfo.Id);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            return obj.GetType() == GetType() && ((RegisteredAppModel)obj).AppInfo.Id == AppInfo.Id;
        }

        public override int GetHashCode() => 0;
    }
}