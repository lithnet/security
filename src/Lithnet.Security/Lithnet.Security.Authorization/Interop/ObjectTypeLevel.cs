﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Lithnet.Security.Authorization.Interop
{
    internal enum ObjectTypeLevel : short //OBJECT_TYPE_LEVEL
    {
        ACCESS_OBJECT_GUID = 0,
        ACCESS_PROPERTY_SET_GUID = 1,
        ACCESS_PROPERTY_GUID = 2,
        ACCESS_MAX_LEVEL = 4
    };
}
