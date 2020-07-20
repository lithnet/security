using System.Runtime.InteropServices;

namespace Lithnet.Security.Authorization.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Luid
    {
        public uint LowPart;

        public uint HighPart;

        public static Luid NullLuid => new Luid { HighPart = 0, LowPart = 0 };
    }
}