using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace GetInjectedThreads
{
    class Program
    {
        //https://docs.microsoft.com/en-au/windows/win32/api/winnt/ns-winnt-memory_basic_information?redirectedfrom=MSDN
        //https://www.codeproject.com/articles/716227/csharp-how-to-scan-a-process-memory


        // Constants
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int THREAD_ALL_ACCESS = 0x001f0ffb;
        const int TOKEN_QUERY = 0x0008;
        const int TOKEN_READ = 0x000a;
        const int PROCESS_WM_READ = 0x0010;
        const int MEM_COMMIT = 0x00001000;
        const int MEM_IMAGE = 0x1000000;

        // Required Interop functions
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("Kernel32.dll")]
        static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("Kernel32.dll")]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, int DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

        [DllImport("Kernel32.dll")]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

        [DllImport("Kernel32.dll")]
        static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, ref int ReturnLength);

        // MEMORY_BASIC_INFORMATION struct required for VirtualQueryEx - to read state and type fields
        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;    // Should be MEM_COMMIT
            public int Protect;  // Maybe check this too?
            public int lType;    // Should be MEM_IMAGE

        }


        static void Main(string[] args)
        {
            // Check if running as administrator first? Or at least check if SeDebugPrivilege enabled?

            // Create array of Process objects for each running process
            Process[] runningProcesses = Process.GetProcesses();

            // Iterate over each process and get all threads by ID
            foreach(Process process in runningProcesses)
            {
                // Get all threads under running process
                ProcessThreadCollection threadCollection = process.Threads;

                // Get handle to the process with desired access level (PROCESS_QUERY_INFORMATION | PROCESS_WM_READ)
                IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id);

                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                MEMORY_BASIC_INFORMATION memBasicInfo = new MEMORY_BASIC_INFORMATION();

                // Iterate over each thread under the process
                foreach (ProcessThread thread in threadCollection)
                {
                    IntPtr threadStartAddress = thread.StartAddress;

                    VirtualQueryEx(processHandle, threadStartAddress, out memBasicInfo, 28);

                    // Check the State and Type fields for the thread's MEMORY_BASIC_INFORMATION
                    if (memBasicInfo.State != MEM_COMMIT)
                    {
                        Console.WriteLine($"Process {process.ProcessName} (PID: {process.Id})\n\tThread: {thread.Id}");
                        Console.WriteLine($"\tThread State != MEM_COMMIT: {memBasicInfo.State}");
                    }

                    if (memBasicInfo.lType != MEM_IMAGE)
                    {
                        Console.WriteLine($"Process {process.ProcessName} (PID: {process.Id})\n\tThread: {thread.Id}");
                        Console.WriteLine($"\tThread Type != MEM_IMAGE: {memBasicInfo.lType}");
                        Console.WriteLine("Possible Thread Injection. Retrieving Access Token...");

                        // Call ReadProcessmemory

                        // Get handle to thread token. If Impersonation is not being used, thread will use Process access token
                        // Try OpenThreadToken(), if it fails, use OpenProcessToken()

                        try
                        {
                            IntPtr threadHandle = OpenThread(THREAD_ALL_ACCESS, false, thread.Id);
                            IntPtr hThreadToken = 0;
                            if(OpenThreadToken(threadHandle, TOKEN_READ | TOKEN_QUERY, false, ref hThreadToken))
                            {

                            }
                        }
                        catch (Exception as e)
                        {
                            throw new NotImplementedException();
                        }
                        finally
                        {
                            //dispose of handles
                        }
                    }
                }

            }


        }
    }
}
