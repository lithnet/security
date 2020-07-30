using System.Runtime.InteropServices;

namespace Lithnet.Security.Authorization.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct AuthzRpcInitInfoClient
    {
        public AuthzRpcClientVersion Version;
        
        [MarshalAs (UnmanagedType.LPWStr)]
        public string ObjectUuid;
        
        [MarshalAs (UnmanagedType.LPWStr)]
        public string Protocol;
        
        [MarshalAs (UnmanagedType.LPWStr)]
        public string Server;
        
        [MarshalAs (UnmanagedType.LPWStr)]
        public string EndPoint;
        
        [MarshalAs (UnmanagedType.LPWStr)]
        public string Options;
        
        [MarshalAs (UnmanagedType.LPWStr)]
        public string ServerSpn;
    }
}