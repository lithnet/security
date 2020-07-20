using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Lithnet.Security.Authorization
{
    internal static class InternalExtensions
    {
        internal static byte[] ToBytes(this SecurityIdentifier s)
        {
            byte[] b = new byte[s.BinaryLength];
            s.GetBinaryForm(b, 0);
            return b;
        }

        internal static byte[] ToBytes(this GenericSecurityDescriptor s)
        {
            byte[] b = new byte[s.BinaryLength];
            s.GetBinaryForm(b, 0);
            return b;
        }
    }
}
