using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace Lithnet.Security.Authorization
{
    public class UnmanagedIdentity
    {
        public SecurityIdentifier SecurityIdentifier { get; }

        public IList<SecurityIdentifier> AdditionalSecurityIdentifiers { get; }

        public UnmanagedIdentity(SecurityIdentifier primarySid)
            : this(primarySid, null)
        {
        }

        public UnmanagedIdentity(SecurityIdentifier primarySid, IEnumerable<SecurityIdentifier> otherSids)
        {
            this.SecurityIdentifier = primarySid;
            this.AdditionalSecurityIdentifiers = otherSids?.ToList();
        }
    }
}
