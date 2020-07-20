using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Lithnet.Security.Authorization.Interop
{
    internal class SafeAuthzContextHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeAuthzContextHandle()
        : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.AuthzFreeContext(this.handle);
        }
    }
}
