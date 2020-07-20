using System;

namespace Lithnet.Security.Authorization.Interop
{
    [Flags]
    internal enum AuthzResourceManagerFlags : uint
    {
        NO_AUDIT = 0x1,
    }
}