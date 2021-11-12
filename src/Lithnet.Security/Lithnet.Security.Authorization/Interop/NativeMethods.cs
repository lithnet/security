using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Lithnet.Security.Authorization.Interop
{
    internal static class NativeMethods
    {
        internal const int InsufficientBuffer = 122;

        internal const string AuthzObjectUuidWithCap = "9a81c2bd-a525-471d-a4ed-49907c0b23da";

        internal const string AuthzObjectUuidWithoutCap = "5fc860e0-6f6e-4fc2-83cd-46324f25e90b";

        internal const string RcpOverTcpProtocol = "ncacn_ip_tcp";

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeRemoteResourceManager(IntPtr rpcInitInfo, out SafeAuthzResourceManagerHandle authRm);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromSid(AuthzInitFlags flags, byte[] rawUserSid, SafeAuthzResourceManagerHandle authRm, IntPtr expirationTime, Luid identifier, IntPtr dynamicGroupArgs, out SafeAuthzContextHandle authzClientContext);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeContextFromToken(AuthzInitFlags flags, SafeAccessTokenHandle hToken, SafeAuthzResourceManagerHandle authRm, IntPtr expirationTime, Luid identifier, IntPtr dynamicGroupArgs, out SafeAuthzContextHandle authzClientContext);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzInitializeResourceManager(AuthzResourceManagerFlags flags, IntPtr pfnAccessCheck, IntPtr pfnComputeDynamicGroups, IntPtr pfnFreeDynamicGroups,
            string szResourceManagerName, out SafeAuthzResourceManagerHandle phAuthzResourceManager);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeContext(IntPtr authzClientContext);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzFreeResourceManager(IntPtr authRm);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AuthzGetInformationFromContext(SafeAuthzContextHandle hAuthzClientContext, AuthzContextInformationClass infoClass, uint bufferSize, out uint pSizeRequired, IntPtr buffer);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool AuthzAccessCheck(AuthzAccessCheckFlags flags, SafeAuthzContextHandle hAuthzClientContext, ref AuthzAccessRequest pRequest, IntPtr AuditEvent, [MarshalAs(UnmanagedType.LPArray)] byte[] pSecurityDescriptor, IntPtr OptionalSecurityDescriptorArray, int OptionalSecurityDescriptorCount, ref AuthzAccessReply pReply, IntPtr phAccessCheckResults);

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool AuthzAddSidsToContext(SafeAuthzContextHandle hAuthzClientContext, IntPtr sids, int sidCount, IntPtr restrictedSids, int restrictedSidCount, out SafeAuthzContextHandle hNewClientContext);
    }
}

/*AUTHZAPI BOOL AuthzAddSidsToContext(
  AUTHZ_CLIENT_CONTEXT_HANDLE  hAuthzClientContext,
  PSID_AND_ATTRIBUTES          Sids,
  DWORD                        SidCount,
  PSID_AND_ATTRIBUTES          RestrictedSids,
  DWORD                        RestrictedSidCount,
  PAUTHZ_CLIENT_CONTEXT_HANDLE phNewAuthzClientContext
);*/