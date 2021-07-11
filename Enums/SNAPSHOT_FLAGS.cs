using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GetInjectedThreads.Enums
{
    [Flags]
    public enum SNAPSHOT_FLAGS : uint
    {
        HeapList = 0x00000001,
        Process = 0x00000002,
        Thread = 0x00000004,
        Module = 0x00000008,
        Module32 = 0x00000010,
        Inherit = 0x80000000,
        All = 0x0000001F,
        NoHeaps = 0x40000000
    }
}
