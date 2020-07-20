using System.Runtime.InteropServices;

namespace Lithnet.Security.Authorization.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct AuthzRpcInitInfoClient
    {
        public AuthzRpcClientVersion Version;
        public string ObjectUuid;
        public string Protocol;
        public string Server;
        public string EndPoint;
        public string Options;
        public string ServerSpn;
    }
}