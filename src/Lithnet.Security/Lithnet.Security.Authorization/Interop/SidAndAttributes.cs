using System;
using System.Runtime.InteropServices;

namespace Lithnet.Security.Authorization.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SidAndAttributes
    {
        public IntPtr Sid;

        public uint Attributes;
    }
}