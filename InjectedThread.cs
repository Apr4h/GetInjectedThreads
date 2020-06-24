using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;

namespace GetInjectedThreads
{
    class InjectedThread
    {
        public string ProcessName { get; set; }
        public int ProcessID { get; set; }
        public string Path { get; set; }
        public string KernelPath { get; set; }
        public string CommandLine { get; set; }
        public bool PathMismatch { get; set; }
        public int ThreadId { get; set; }
        public string AllocatedMemoryProtection { get; set; }
        public string MemoryProtection { get; set; }
        public string MemoryState { get; set; }
        public string MemoryType { get; set; }
        public int BasePriority { get; set; }
        public bool IsUniqueThreadToken { get; set; }
        public string Integrity { get; set; }
        public string Privilege { get; set; }
        public int LogonId { get; set; }
        public string SecurityIdentifier { get; set; }
        public string Username { get; set; }
        public string LogonSessionStartTime { get; set; }
        public string LogonType { get; set; }
        public string AuthenticationPackage { get; set; }
        public IntPtr BaseAddress { get; set; }
        public int Size { get; set; }
        public byte[] Bytes { get; set; }
    }
}
