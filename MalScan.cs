using GetInjectedThreads.Yara;
using libyaraNET;
using System;
using System.Collections.Generic;


namespace GetInjectedThreads
{
    public static class MalScan
    {
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
                                Console.WriteLine($"Data:       {match.Data}");
                                Console.WriteLine($"Base:       {match.Base}");
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
    }
}
