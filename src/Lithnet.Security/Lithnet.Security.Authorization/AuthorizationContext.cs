using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Lithnet.AccessManager;
using Lithnet.Security.Authorization.Interop;
using Microsoft.Win32.SafeHandles;

namespace Lithnet.Security.Authorization
{
    public sealed class AuthorizationContext : IDisposable
    {
        private readonly SafeAuthzContextHandle authzContext;

        private SafeAuthzResourceManagerHandle authzRm;

        /// <summary>
        /// Gets the server that the authorization context was established against. This value is null if the local server was used.
        /// </summary>
        public string Server { get; private set; }

        /// <summary>
        /// Gets the security identifier of the principal represented by this authorization context
        /// </summary>
        public SecurityIdentifier SecurityIdentifer { get; private set; }

        /// <summary>
        /// Initializes a new instance of the AuthorizationContext class
        /// </summary>
        /// <param name="principal">The security identifier of the principal to build the authorization context for</param>
        public AuthorizationContext(SecurityIdentifier principal) : this(principal, null, false) { }

        /// <summary>
        /// Initializes a new instance of the AuthorizationContext class
        /// </summary>
        /// <param name="principal">The security identifier of the principal to build the authorization context for</param>
        /// <param name="server">The remote server to use to build the authorization context</param>
        public AuthorizationContext(SecurityIdentifier principal, string server) : this(principal, server, false) { }

        /// <summary>
        /// Initializes a new instance of the AuthorizationContext class
        /// </summary>
        /// <param name="principal">The security identifier of the principal to build the authorization context for</param>
        /// <param name="server">The remote server to use to build the authorization context</param>
        /// <param name="allowLocalFallback">A value that indicates if automatically falling back to the local server is allowed if the remote context fails to be established. If fallback occurs, the context will be initialized with the <see cref="Server"/> field set to null</param>
        public AuthorizationContext(SecurityIdentifier principal, string server, bool allowLocalFallback)
        {
            this.SecurityIdentifer = principal;

            this.authzRm = InitializeResourceManager(server, allowLocalFallback, out bool localFallbackOccurred);

            if (localFallbackOccurred)
            {
                this.Server = null;
            }
            else
            {
                this.Server = server;
            }

            this.authzContext = InitializeAuthorizationContextFromSid(this.authzRm, this.SecurityIdentifer);
        }

        /// <summary>
        /// Initializes a new instance of the AuthorizationContext class
        /// </summary>
        /// <param name="accessToken">The access token of the principal to build the authorization context for</param>
        public AuthorizationContext(SafeAccessTokenHandle accessToken) : this(accessToken, null, false) { }

        /// <summary>
        /// Initializes a new instance of the AuthorizationContext class
        /// </summary>
        /// <param name="accessToken">The access token of the principal to build the authorization context for</param>
        /// <param name="server">The remote server to use to build the authorization context</param>
        public AuthorizationContext(SafeAccessTokenHandle accessToken, string server) : this(accessToken, server, false) { }

        /// <summary>
        /// Initializes a new instance of the AuthorizationContext class
        /// </summary>
        /// <param name="accessToken">The access token of the principal to build the authorization context for</param>
        /// <param name="server">The remote server to use to build the authorization context</param>
        /// <param name="allowLocalFallback">A value that indicates if automatically falling back to the local server is allowed if the remote context fails to be established. If fallback occurs, the context will be initialized with the <see cref="Server"/> field set to null</param>
        public AuthorizationContext(SafeAccessTokenHandle accessToken, string server, bool allowLocalFallback)
        {
            this.authzRm = InitializeResourceManager(server, allowLocalFallback, out bool localFallbackOccurred);
            this.SecurityIdentifer = GetSecurityIdentifierFromAccessToken(accessToken.DangerousGetHandle());

            if (localFallbackOccurred)
            {
                this.Server = null;
            }
            else
            {
                this.Server = server;
            }

            this.authzContext = InitializeAuthorizationContextFromToken(this.authzRm, accessToken);
        }

        /// <summary>
        /// Gets a list of the principal's token groups
        /// </summary>
        /// <returns>A list of security identifiers representing the groups present in the principal's security token</returns>
        public IEnumerable<SecurityIdentifier> GetTokenGroups()
        {
            uint sizeRequired = 0;

            if (!NativeMethods.AuthzGetInformationFromContext(this.authzContext, AuthzContextInformationClass.AuthzContextInfoGroupsSids, sizeRequired, out sizeRequired, IntPtr.Zero))
            {
                Win32Exception e = new Win32Exception(Marshal.GetLastWin32Error());

                if (e.NativeErrorCode != NativeMethods.InsufficientBuffer)
                {
                    throw new AuthorizationContextException("AuthzGetInformationFromContext failed", e);
                }
            }

            SafeAllocHGlobalHandle structure = new SafeAllocHGlobalHandle(sizeRequired);
            IntPtr pstructure = structure.DangerousGetHandle();

            if (!NativeMethods.AuthzGetInformationFromContext(this.authzContext, AuthzContextInformationClass.AuthzContextInfoGroupsSids, sizeRequired, out sizeRequired, pstructure))
            {
                throw new AuthorizationContextException("AuthzGetInformationFromContext failed", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            TokenGroups groups = Marshal.PtrToStructure<TokenGroups>(pstructure);

            IntPtr current = IntPtr.Add(pstructure, Marshal.OffsetOf<TokenGroups>(nameof(groups.Groups)).ToInt32());

            for (int i = 0; i < groups.GroupCount; i++)
            {
                SidAndAttributes sidAndAttributes = (SidAndAttributes)Marshal.PtrToStructure(current, typeof(SidAndAttributes));
                yield return new SecurityIdentifier(sidAndAttributes.Sid);
                current = IntPtr.Add(current, Marshal.SizeOf(typeof(SidAndAttributes)));
            }
        }

        /// <summary>
        /// Returns a value indicating whether the specified security identifier is present in principal's authorization context
        /// </summary>
        /// <param name="sidToCheck">A security identifier to look for in the principal's authorization context</param>
        /// <returns>True if the context contains the specified SID, otherwise false</returns>
        public bool ContainsSid(SecurityIdentifier sidToCheck)
        {
            foreach (SecurityIdentifier sid in this.GetTokenGroups())
            {
                if (sid == sidToCheck)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Returns a value indicating if the principal is authorized for the requested access in a given security descriptor
        /// </summary>
        /// <param name="securityDescriptor">The security descriptor to check</param>
        /// <param name="requestedAccessMask">The access mask desired</param>
        /// <returns>True if the request is allowed, false if it is denied.</returns>
        public bool AccessCheck(GenericSecurityDescriptor securityDescriptor, int requestedAccessMask)
        {
            return AccessCheck(securityDescriptor, requestedAccessMask, null);
        }

        /// <summary>
        /// Returns a value indicating if the principal is authorized for the requested access in a given security descriptor
        /// </summary>
        /// <param name="securityDescriptor">The security descriptor to check</param>
        /// <param name="requestedAccessMask">The access mask desired</param>
        /// <param name="selfSid">The SID to use when the security descriptor contains the 'SELF' principal</param>
        /// <returns>True if the request is allowed, false if it is denied.</returns>
        public bool AccessCheck(GenericSecurityDescriptor securityDescriptor, int requestedAccessMask, SecurityIdentifier selfSid)
        {
            return AccessCheck(new List<GenericSecurityDescriptor> { securityDescriptor }, requestedAccessMask, selfSid);
        }

        /// <summary>
        /// Returns a value indicating if the principal is authorized for the requested access in any given security descriptor. The access evaluated is the logical concatination of all the supplied security descriptors
        /// </summary>
        /// <param name="securityDescriptors">The security descriptors to check</param>
        /// <param name="requestedAccessMask">The access mask desired</param>
        /// <returns>True if the request is allowed, false if it is denied.</returns>
        public bool AccessCheck(IList<GenericSecurityDescriptor> securityDescriptors, int requestedAccessMask)
        {
            return AccessCheck(securityDescriptors, requestedAccessMask, null);
        }

        /// <summary>
        /// Returns a value indicating if the principal is authorized for the requested access in any given security descriptor. The access evaluated is the logical concatination of all the supplied security descriptors
        /// </summary>
        /// <param name="securityDescriptors">The security descriptors to check</param>
        /// <param name="requestedAccessMask">The access mask desired</param>
        /// <param name="selfSid">The SID to use when the security descriptor contains the 'SELF' principal</param>
        /// <returns>True if the request is allowed, false if it is denied.</returns>
        public bool AccessCheck(IList<GenericSecurityDescriptor> securityDescriptors, int requestedAccessMask, SecurityIdentifier selfSid)
        {
            if (securityDescriptors == null)
            {
                throw new ArgumentNullException(nameof(securityDescriptors));
            }

            if (securityDescriptors.Count == 0)
            {
                return false;
            }

            GenericSecurityDescriptor primarySecurityDescriptor = securityDescriptors[0];
            List<GenericSecurityDescriptor> otherSecurityDescriptors = securityDescriptors.ToList();
            otherSecurityDescriptors.RemoveAt(0);

            byte[] primarySecurityDescriptorBytes = primarySecurityDescriptor.ToBytes();

            if (primarySecurityDescriptor.Owner == null)
            {
                throw new Win32Exception(87, "The security descriptor must include an owner");
            }

            AuthzAccessRequest request = new AuthzAccessRequest();
            request.PrincipalSelfSid = selfSid?.ToBytes();
            request.DesiredAccess = requestedAccessMask;

            AuthzAccessReply reply = new AuthzAccessReply();
            SafeAllocHGlobalHandle accessMaskReply = new SafeAllocHGlobalHandle(Marshal.SizeOf<uint>());
            SafeAllocHGlobalHandle errorReply = new SafeAllocHGlobalHandle(Marshal.SizeOf<uint>());
            SafeAllocHGlobalHandle saclReply = new SafeAllocHGlobalHandle(Marshal.SizeOf<uint>());

            reply.ResultListLength = 1;
            reply.GrantedAccessMask = accessMaskReply.DangerousGetHandle();
            reply.SaclEvaluationResults = saclReply.DangerousGetHandle();
            reply.Error = errorReply.DangerousGetHandle();

            IntPtr pOthers = IntPtr.Zero;
            int othersCount = otherSecurityDescriptors?.Count ?? 0;
            if (othersCount > 0)
            {
                List<byte[]> list = new List<byte[]>();
                foreach (var item in otherSecurityDescriptors)
                {
                    list.Add(item.ToBytes());
                }

                LpArrayOfByteArrayConverter r = new LpArrayOfByteArrayConverter(list);
                pOthers = r.Ptr;
            }

            if (!NativeMethods.AuthzAccessCheck(AuthzAccessCheckFlags.None, this.authzContext, ref request, IntPtr.Zero, primarySecurityDescriptorBytes, pOthers, othersCount, ref reply, IntPtr.Zero))
            {
                throw new AuthorizationContextException("AuthzAccessCheck failed", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            int maskResult = Marshal.ReadInt32(reply.GrantedAccessMask);
            int error = Marshal.ReadInt32(reply.Error);

            if (error == 0)
            {
                return (requestedAccessMask & maskResult) == requestedAccessMask;
            }

            return false;
        }

        private static SecurityIdentifier GetSecurityIdentifierFromAccessToken(IntPtr accessToken)
        {
            return new WindowsIdentity(accessToken)?.User;
        }

        private static SafeAuthzContextHandle InitializeAuthorizationContextFromToken(SafeAuthzResourceManagerHandle authzRm, SafeAccessTokenHandle accessToken)
        {
            if (!NativeMethods.AuthzInitializeContextFromToken(AuthzInitFlags.Default, accessToken, authzRm, IntPtr.Zero, Luid.NullLuid, IntPtr.Zero, out SafeAuthzContextHandle userClientCtxt))
            {
                int errorCode = Marshal.GetLastWin32Error();

                if (errorCode == 5)
                {
                    throw new AuthorizationContextException("AuthzInitializeContextFromSid failed", new Win32Exception(errorCode, "Access was denied. Please ensure that \r\n1) The service account is a member of the built-in group called 'Windows Authorization Access Group' in the domain where the computer object is located\r\n2) The service account is a member of the built-in group called 'Access Control Assistance Operators' in the domain where the computer object is located"));
                }

                throw new AuthorizationContextException("AuthzInitializeContextFromSid failed", new Win32Exception(errorCode));
            }

            return userClientCtxt;
        }

        private static SafeAuthzContextHandle InitializeAuthorizationContextFromSid(SafeAuthzResourceManagerHandle authzRm, SecurityIdentifier sid)
        {
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            if (!NativeMethods.AuthzInitializeContextFromSid(AuthzInitFlags.Default, sidBytes, authzRm, IntPtr.Zero, Luid.NullLuid, IntPtr.Zero, out SafeAuthzContextHandle userClientCtxt))
            {
                int errorCode = Marshal.GetLastWin32Error();

                if (errorCode == 5)
                {
                    throw new AuthorizationContextException("AuthzInitializeContextFromSid failed", new Win32Exception(errorCode, "Access was denied. Please ensure that \r\n1) The service account is a member of the built-in group called 'Windows Authorization Access Group' in the domain where the computer object is located\r\n2) The service account is a member of the built-in group called 'Access Control Assistance Operators' in the domain where the computer object is located"));
                }

                throw new AuthorizationContextException("AuthzInitializeContextFromSid failed", new Win32Exception(errorCode));
            }

            return userClientCtxt;
        }

        private static SafeAuthzResourceManagerHandle InitializeResourceManager(string authzServerName, bool allowLocalFallback, out bool localFallbackOccurred)
        {
            SafeAuthzResourceManagerHandle authzRm = null;
            localFallbackOccurred = false;

            if (!string.IsNullOrWhiteSpace(authzServerName) && Environment.OSVersion.Version.Major < 6 || (Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor < 2))
            {
                throw new PlatformNotSupportedException("Specifying a remote server name requires Windows 8 or Windows Server 2012");
            }

            try
            {
                if (!string.IsNullOrWhiteSpace(authzServerName))
                {
                    AuthzRpcInitInfoClient client = new AuthzRpcInitInfoClient
                    {
                        Version = AuthzRpcClientVersion.V1,
                        ObjectUuid = NativeMethods.AuthzObjectUuidWithoutCap,
                        Protocol = NativeMethods.RcpOverTcpProtocol,
                        Server = authzServerName
                    };


                    SafeAllocHGlobalHandle clientInfo = new SafeAllocHGlobalHandle(Marshal.SizeOf(typeof(AuthzRpcInitInfoClient)));
                    IntPtr pClientInfo = clientInfo.DangerousGetHandle();
                    Marshal.StructureToPtr(client, pClientInfo, false);

                    if (!NativeMethods.AuthzInitializeRemoteResourceManager(pClientInfo, out authzRm))
                    {
                        throw new AuthorizationContextException("AuthzInitializeRemoteResourceManager failed", new Win32Exception(Marshal.GetLastWin32Error()));
                    }
                }
            }
            catch (Exception)
            {
                if (allowLocalFallback)
                {
                    localFallbackOccurred = true;
                }
                else
                {
                    throw;
                }
            }

            if (authzRm == null || authzRm.IsInvalid)
            {
                if (!NativeMethods.AuthzInitializeResourceManager(AuthzResourceManagerFlags.NO_AUDIT, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, null, out authzRm))
                {
                    throw new AuthorizationContextException("AuthzInitializeResourceManager failed", new Win32Exception(Marshal.GetLastWin32Error()));
                }
            }

            return authzRm;
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                authzContext?.Dispose();
                authzRm?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~AuthorizationContext()
        {
            Dispose(false);
        }
    }
}
