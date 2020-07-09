using GetInjectedThreads.Yara;
using libyaraNET;
using System;
using System.Collections.Generic;


namespace GetInjectedThreads
{
    public static class MalScan
    {
        private static readonly byte[] pattern = new byte[] { 0x69, 0x68, 0x69, 0x68, 0x69 };
        private const int configSize = 0x1000;

        // Pattern, name, size for each piece of configuration information
        private static readonly List<Tuple<byte[], string, int>> configInfo = new List<Tuple<byte[], string, int>> {
                Tuple.Create(new byte[] { 0x00, 0x01, 0x00, 0x01, 0x00, 0x02 }, "BeaconType\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x02, 0x00, 0x01, 0x00, 0x02 }, "Port\t\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x03, 0x00, 0x02, 0x00, 0x04 }, "Polling(ms)\t\t:", 0x4),
                Tuple.Create(new byte[] { 0x00, 0x04, 0x00, 0x02, 0x00, 0x04 }, "Unknown1\t\t:", 0x4),
                Tuple.Create(new byte[] { 0x00, 0x05, 0x00, 0x01, 0x00, 0x02 }, "Jitter\t\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x06, 0x00, 0x01, 0x00, 0x02 }, "Maxdns\t\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x07, 0x00, 0x03, 0x01, 0x00 }, "Unknown2\t\t:", 0x100),
                Tuple.Create(new byte[] { 0x00, 0x08, 0x00, 0x03, 0x01, 0x00 }, "C2Server\t\t:", 0x100),
                Tuple.Create(new byte[] { 0x00, 0x09, 0x00, 0x03, 0x00, 0x80 }, "UserAgent\t\t:", 0x80),
                Tuple.Create(new byte[] { 0x00, 0x0a, 0x00, 0x03, 0x00, 0x40 }, "HTTP_Method2_Path\t:", 0x40),
                Tuple.Create(new byte[] { 0x00, 0x0b, 0x00, 0x03, 0x01, 0x00 }, "Unknown3\t\t:", 0x100),
                Tuple.Create(new byte[] { 0x00, 0x0c, 0x00, 0x03, 0x01, 0x00 }, "Header1\t\t\t:", 0x100),
                Tuple.Create(new byte[] { 0x00, 0x0d, 0x00, 0x03, 0x01, 0x00 }, "Header2\t\t\t:", 0x100),
                Tuple.Create(new byte[] { 0x00, 0x0e, 0x00, 0x03, 0x00, 0x40 }, "Injection_Process\t:", 0x40),
                Tuple.Create(new byte[] { 0x00, 0x0f, 0x00, 0x03, 0x00, 0x80 }, "PipeName\t\t:", 0x80),
                Tuple.Create(new byte[] { 0x00, 0x10, 0x00, 0x01, 0x00, 0x02 }, "Year\t\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x11, 0x00, 0x01, 0x00, 0x02 }, "Month\t\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x12, 0x00, 0x01, 0x00, 0x02 }, "Day\t\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x13, 0x00, 0x02, 0x00, 0x04 }, "DNS_idle\t\t:", 0x4),
                Tuple.Create(new byte[] { 0x00, 0x14, 0x00, 0x02, 0x00, 0x04 }, "DNS_sleep(ms)\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x1a, 0x00, 0x03, 0x00, 0x10 }, "Method1\t\t\t:", 0x10),
                Tuple.Create(new byte[] { 0x00, 0x1b, 0x00, 0x03, 0x00, 0x10 }, "Method2\t\t\t:", 0x10),
                Tuple.Create(new byte[] { 0x00, 0x1c, 0x00, 0x02, 0x00, 0x04 }, "Unknown4\t\t:", 0x4),
                Tuple.Create(new byte[] { 0x00, 0x1d, 0x00, 0x03, 0x00, 0x40 }, "Spawnto_x86\t\t:", 0x40),
                Tuple.Create(new byte[] { 0x00, 0x1e, 0x00, 0x03, 0x00, 0x40 }, "Spawnto_x64\t\t:", 0x40),
                Tuple.Create(new byte[] { 0x00, 0x1f, 0x00, 0x01, 0x00, 0x02 }, "Unknown5\t\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x20, 0x00, 0x03, 0x00, 0x80 }, "Proxy_HostName\t\t:", 0x80),
                Tuple.Create(new byte[] { 0x00, 0x21, 0x00, 0x03, 0x00, 0x40 }, "Proxy_UserName\t\t:", 0x40),
                Tuple.Create(new byte[] { 0x00, 0x22, 0x00, 0x03, 0x00, 0x40 }, "Proxy_Password\t\t:", 0x40),
                Tuple.Create(new byte[] { 0x00, 0x23, 0x00, 0x01, 0x00, 0x02 }, "Proxy_AccessType\t:", 0x2),
                Tuple.Create(new byte[] { 0x00, 0x24, 0x00, 0x01, 0x00, 0x02 }, "create_remote_thread\t:", 0x2)
        };


        /// <summary>
        /// Perform YARA scan on process memory to detect meterpreter or Cobalt Strike payloads.
        /// </summary>
        /// <param name="processBytes">Byte array of target process to be scanned</param>
        public static void YaraScan(byte[] processBytes)
        {
            using (var ctx = new YaraContext())
            {
                Rules rules = null;

                try
                {
                    using (Compiler compiler = new Compiler())
                    {
                        // Retrieve YARA rules from YaraRules static class and compile them for scanning
                        foreach (string rule in YaraRules.meterpreterRules)
                        {
                            compiler.AddRuleString(rule);
                        } 

                        compiler.AddRuleString(YaraRules.cobaltStrikeRule);

                        rules = compiler.GetRules();
                    }

                    // Perform scan on process memory byte[]
                    Scanner scanner = new Scanner();
                    var results = scanner.ScanMemory(processBytes, rules);

                    // Check for scan results and print matches to console 
                    foreach (ScanResult result in results)
                    {
                        foreach (KeyValuePair<string, List<Match>> matches in result.Matches)
                        {
                            Console.WriteLine($"Found Match {matches.Key}");
                            foreach (Match match in matches.Value)
                            {
                                Console.WriteLine($"Offset:     {match.Offset}");
                                Console.WriteLine($"AsString:   {match.AsString()}\n\n");
                            }
                        }
                    }
                }
                finally
                {
                    if (rules != null) rules.Dispose();
                }
            }
        }


        public static void GetCobaltStrikeConfig(byte[] processBytes, ulong matchOffset)
        {


        }

    }
}
