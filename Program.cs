using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security.Principal;
using System.Text;
using System.Diagnostics.Eventing.Reader;

namespace GetInjectedThreads
{
    class Program
    {
        //https://docs.microsoft.com/en-au/windows/win32/api/winnt/ns-winnt-memory_basic_information?redirectedfrom=MSDN
        //https://www.codeproject.com/articles/716227/csharp-how-to-scan-a-process-memory


        // Constants
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int THREAD_ALL_ACCESS = 0x001f0ffb;
        const int PROCESS_ALL_ACCESS = 0x001f1ffb;
        const int TOKEN_QUERY = 0x0008;
        const int TOKEN_READ = 0x000a;
        const int PROCESS_WM_READ = 0x0010;
        const int MEM_COMMIT = 0x00001000;
        const int MEM_IMAGE = 0x1000000;

        // Required Interop functions
        [DllImport("shell32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsUserAnAdmin();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("Kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern Boolean OpenThreadToken(IntPtr ThreadHandle, TokenAccessFlags DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern Boolean OpenProcessToken(IntPtr ProcessHandle, ProcessAccessFlags DesiredAccess, out IntPtr TokenHandle);

        [DllImport("Kernel32.dll")]
        static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationThread(IntPtr threadHandle, ThreadInfoClass threadInformationClass, IntPtr threadInformation, int threadInformationLength, IntPtr returnLengthPtr);

        [HandleProcessCorruptedStateExceptions]
        static void Main(string[] args)
        {
            // Check if running as administrator first? Or at least check if SeDebugPrivilege enabled?
            if(IsUserAnAdmin() == false)
            {
                Console.WriteLine("Program is not running as Administrator. Exiting...");
                System.Environment.Exit(1);
            }

            List<InjectedThread> injectedThreads = new List<InjectedThread>();

            // Create array of Process objects for each running process
            Process[] runningProcesses = Process.GetProcesses();

            // Iterate over each process and get all threads by ID
            foreach (Process process in runningProcesses)
            {
                // PID 0 and PID 4 aren't valid targets for injection
                if (process.Id != 0 && process.Id != 4)
                {
                    // Get all threads under running process
                    ProcessThreadCollection threadCollection = process.Threads;
                    IntPtr hProcess;

                    try
                    {
                        // Get handle to the process
                        hProcess = OpenProcess(ProcessAccessFlags.All, false, process.Id);
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        Console.WriteLine($"Couldn't get handle to process: {process.Id} - System.ComponentModel.Win32Exception - Access Is Denied");
                        continue;
                    }
                    catch (System.InvalidOperationException)
                    {
                        Console.WriteLine($"Couldn't get handle to process {process.Id} - System.InvalidOperationException - Process has Exited");
                        continue;
                    }


                    // Iterate over each thread under the process
                    foreach (ProcessThread thread in threadCollection)
                    {
                        // Get handle to the thread
                        IntPtr hThread = OpenThread(ThreadAccess.AllAccess, false, thread.Id);

                        // Create buffer to store pointer to the thread's base address - NTQueryInformationThread writes to this buffer
                        IntPtr buf = Marshal.AllocHGlobal(IntPtr.Size);

                        // Retrieve thread's Win32StartAddress - Different to thread.StartAddress
                        Int32 result = NtQueryInformationThread(hThread, ThreadInfoClass.ThreadQuerySetWin32StartAddress, buf, IntPtr.Size, IntPtr.Zero);

                        if(result == 0)
                        {
                            // Need to Marshal Win32 type pointer from CLR type IntPtr to access the thread's base address via pointer
                            IntPtr threadBaseAddress = Marshal.ReadIntPtr(buf);

                            // Retrieve MEMORY_BASIC_INFORMATION struct for each thread - assumes 64bit processes, otherwise need to use MEMORY_BASIC_INFORMATION32
                            MEMORY_BASIC_INFORMATION64 memBasicInfo = new MEMORY_BASIC_INFORMATION64();
                            VirtualQueryEx(hProcess, threadBaseAddress, out memBasicInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));

                            // Check the State and Type fields for the thread's MEMORY_BASIC_INFORMATION
                            // Resolve to false suggests code running from this thread does not have a corresponding image file on disk, likely code injection
                            if (memBasicInfo.State == MemoryBasicInformationState.MEM_COMMIT && memBasicInfo.Type != MemoryBasicInformationType.MEM_IMAGE)
                            {
                                // Create new InjectedThread object and set initial variables
                                InjectedThread injectedThread = new InjectedThread()
                                {
                                    ProcessName = process.ProcessName,
                                    ProcessID = process.Id,
                                    ThreadId = thread.Id,
                                    BaseAddress = threadBaseAddress,
                                    Path = process.MainModule.FileName,
                                    CommandLine = GetProcessCommandLine(process),
                                    MemoryState = Enum.GetName(typeof(MemoryBasicInformationState), memBasicInfo.State),
                                    MemoryType = Enum.GetName(typeof(MemoryBasicInformationType), memBasicInfo.Type),
                                    MemoryProtection = Enum.GetName(typeof(MemoryBasicInformationProtection), memBasicInfo.Protect),
                                    AllocatedMemoryProtection = Enum.GetName(typeof(MemoryBasicInformationProtection), memBasicInfo.AllocationProtect),
                                    BasePriority = thread.BasePriority,
                                    ThreadStartTime = thread.StartTime
                                };

                                // Get handle to thread token. If Impersonation is not being used, thread will use Process access token
                                IntPtr hToken;

                                // Try OpenThreadToken(), if it fails, use OpenProcessToken()
                                if (OpenThreadToken(hThread, TokenAccessFlags.TOKEN_ALL_ACCESS, false, out hToken) == false)
                                {
                                    int error = Marshal.GetLastWin32Error();
                                    Console.WriteLine($"OpenThreadToken() Error: {error}\nThread ID {thread.Id}\nOpening Process Token instead...");

                                    // Thread doesn't have a unique token
                                    injectedThread.IsUniqueThreadToken = false;

                                    // Open process token instead
                                    if(OpenProcessToken(hProcess, ProcessAccessFlags.All, out hToken) == false)
                                    {
                                        error = Marshal.GetLastWin32Error();
                                        Console.WriteLine($"OpenProcessToken() Error: {error}\nProcess ID {process.Id}");
                                    }
                                }
                                else
                                {
                                    injectedThread.IsUniqueThreadToken = true;
                                }


                               

                            }
                        }
                    }
                }
            }
        }    


        // Get commandline for a process using WMI. Catch exceptions where either "Access Denied" or process has exited
        static string GetProcessCommandLine(Process process)
        {
            string commandLine = null;

            try
            {
                // Requres reference to System.Management.dll assembly for WMI class
                using (var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}"))
                {
                    using (var matchEnum = searcher.Get().GetEnumerator())
                    {
                        if (matchEnum.MoveNext())
                        {
                            commandLine = matchEnum.Current["CommandLine"]?.ToString();
                        }
                    }
                }
            }
            // Catch process exited exception
            catch(InvalidOperationException) 
            {
                Console.WriteLine($"Couldn't get CommandLine for PID {process.Id} - Process has exited");
            }

            return commandLine;
        }


        static string QueryToken(IntPtr hToken, TOKEN_INFORMATION_CLASS tokenInformationClass)
        {
            /* GetTokenInformation
            * SID              TokenUser           (1)
            * Privileges       TokenPrivileges     (3)
            * LogonSession     TokenOrigin         (17)
            * Integrity        TokenIntegrityLevel (25)
            */

            int tokenInformationLength = 0;
            bool result;

            // First need to get the length of TokenInformation
            result = GetTokenInformation(hToken, tokenInformationClass, IntPtr.Zero, tokenInformationLength, out tokenInformationLength);

            switch (tokenInformationClass)
            {
                case TOKEN_INFORMATION_CLASS.TokenUser:

                    IntPtr tokenInformation = Marshal.AllocHGlobal(tokenInformationLength);
                    
            }
            return "test";
        }
    }
}
