using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Lithnet.Security.Authorization
{
    public interface IAuthorizationContext : IDisposable
    {
        SecurityIdentifier SecurityIdentifer { get; }

        string Server { get; }

        bool AccessCheck(GenericSecurityDescriptor securityDescriptor, int requestedAccessMask);

        bool AccessCheck(GenericSecurityDescriptor securityDescriptor, int requestedAccessMask, SecurityIdentifier selfSid);

        bool AccessCheck(IList<GenericSecurityDescriptor> securityDescriptors, int requestedAccessMask);

        bool AccessCheck(IList<GenericSecurityDescriptor> securityDescriptors, int requestedAccessMask, SecurityIdentifier selfSid);

        bool ContainsSid(SecurityIdentifier sidToCheck);

        IEnumerable<SecurityIdentifier> GetTokenGroups();
    }
}