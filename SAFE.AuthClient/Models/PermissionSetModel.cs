﻿
namespace SAFE.AuthClient.Models
{
    public class PermissionSetModel
    {
        public bool Delete { get; set; }
        public bool Insert { get; set; }
        public bool ManagePermissions { get; set; }
        public bool Read { get; set; }
        public bool Update { get; set; }
    }
}