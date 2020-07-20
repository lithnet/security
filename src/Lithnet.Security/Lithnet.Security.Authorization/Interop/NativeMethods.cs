using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Lithnet.Security.Authorization.Interop
{
    internal static class NativeMethods
    {
        internal const int InsufficientBuffer = 122;

        internal const string AuthzObjectUuidWithcap = "9a81c2bd-a525-471d-a4ed-49907c0b23da";

        internal const string RcpOverTcpProtocol = "ncacn_ip_tcp";

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeRemoteResourceManager(IntPtr rpcInitInfo, out SafeAuthzResourceManagerHandle authRm);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromSid(AuthzInitFlags flags, byte[] rawUserSid, SafeAuthzResourceManagerHandle authRm, IntPtr expirationTime, Luid identifier, IntPtr dynamicGroupArgs, out SafeAuthzContextHandle authzClientContext);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromToken(AuthzInitFlags flags, SafeAccessTokenHandle hToken, SafeAuthzResourceManagerHandle authRm, IntPtr expirationTime, Luid identifier, IntPtr dynamicGroupArgs, out SafeAuthzContextHandle authzClientContext);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeResourceManager(AuthzResourceManagerFlags flags, IntPtr pfnAccessCheck, IntPtr pfnComputeDynamicGroups, IntPtr pfnFreeDynamicGroups,
            string szResourceManagerName, out SafeAuthzResourceManagerHandle phAuthzResourceManager);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeContext(IntPtr authzClientContext);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeResourceManager(IntPtr authRm);

        [DllImport("authz.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzGetInformationFromContext(SafeAuthzContextHandle hAuthzClientContext, AuthzContextInformationClass infoClass, uint bufferSize, out uint pSizeRequired, IntPtr buffer);

        [DllImport("authz.dll", SetLastError = true)]
        internal static extern bool AuthzAccessCheck(AuthzAccessCheckFlags flags, SafeAuthzContextHandle hAuthzClientContext, ref AuthzAccessRequest pRequest, IntPtr AuditEvent, [MarshalAs(UnmanagedType.LPArray)] byte[] pSecurityDescriptor, IntPtr OptionalSecurityDescriptorArray, int OptionalSecurityDescriptorCount, ref AuthzAccessReply pReply, IntPtr phAccessCheckResults);

    }
}