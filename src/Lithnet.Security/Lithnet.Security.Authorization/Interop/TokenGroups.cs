using System.Runtime.InteropServices;

namespace Lithnet.Security.Authorization.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    public struct TokenGroups
    {
        public uint GroupCount;

        [MarshalAs(UnmanagedType.ByValArray)]
        public SidAndAttributes[] Groups;
    }
}