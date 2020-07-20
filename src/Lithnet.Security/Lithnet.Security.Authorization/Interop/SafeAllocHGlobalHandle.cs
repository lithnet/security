﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Lithnet.Security.Authorization.Interop
{
    internal class SafeAllocHGlobalHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeAllocHGlobalHandle() : base(true)
        { 
        }

        public SafeAllocHGlobalHandle(int length) : this()
        {
            this.SetHandle(Marshal.AllocHGlobal(length));
        }

        public SafeAllocHGlobalHandle(uint length) : this((int)length)
        {
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(this.handle);
            return true;
        }
    }
}
