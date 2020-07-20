using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Lithnet.Security.Authorization.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ObjectTypeList //OBJECT_TYPE_LIST
    {
        public ObjectTypeLevel Level;
        public short Sbz;
        public IntPtr ObjectType;
    };
}
