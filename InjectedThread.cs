using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;
using System.Threading;

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
        public string Privileges { get; set; }
        public string LogonId { get; set; }
        public string SecurityIdentifier { get; set; }
        public string Username { get; set; }
        public DateTime LogonSessionStartTime { get; set; }
        public string LogonType { get; set; }
        public string AuthenticationPackage { get; set; }
        public IntPtr BaseAddress { get; set; }
        public int Size { get; set; }
        public byte[] Bytes { get; set; }
        public DateTime ThreadStartTime { get; set; }

        public void OutputToConsole()
        {
            const string format = "{0,-32} : {1}";

            Console.WriteLine(format, "ProcessName", ProcessName);
            Console.WriteLine(format, "ProcessId", ProcessID);
            Console.WriteLine(format, "Path", Path);
            Console.WriteLine(format, "KernelPath", KernelPath);
            Console.WriteLine(format, "CommandLine", CommandLine);
            Console.WriteLine(format, "PathMismatch", PathMismatch);
            Console.WriteLine(format, "ThreadId", ThreadId);
            Console.WriteLine(format, "AllocatedMemoryProtection", AllocatedMemoryProtection);
            Console.WriteLine(format, "MemoryProtection", MemoryProtection);
            Console.WriteLine(format, "MemoryState", MemoryState);
            Console.WriteLine(format, "MemoryType", MemoryType);
            Console.WriteLine(format, "BasePriority", BasePriority);
            Console.WriteLine(format, "IsUniqueThreadToken", IsUniqueThreadToken);
            Console.WriteLine(format, "Integrity", Integrity);
            Console.WriteLine(format, "Privileges", Privileges);
            Console.WriteLine(format, "LogonId", LogonId);
            Console.WriteLine(format, "SecurityIdentifier", SecurityIdentifier);
            Console.WriteLine(format, "Username", Username);
            Console.WriteLine(format, "LogonSessionStartTime", LogonSessionStartTime);
            Console.WriteLine(format, "LogonType", LogonType);
            Console.WriteLine(format, "AuthenticationPackage", AuthenticationPackage);
            Console.WriteLine(format, "BaseAddress", BaseAddress);
            Console.WriteLine(format, "Size", Size);
            Console.WriteLine(format, "Bytes", ByteArrayToString(Bytes));
        }

        /// <summary>
        /// Returns first 10 bytes of byte array as a its string representation for nicer output to console
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        private string ByteArrayToString(byte[] bytes)
        {
            var stringBuilder = new StringBuilder("{ ");
            for(int i = 0; i < 10; i++)
            {
                stringBuilder.Append(bytes[i] + ", ");
            }
            stringBuilder.Append("... }");
            return stringBuilder.ToString();
        }
    }
}
