using CobaltStrikeConfigParser;
using GetInjectedThreads.Yara;
using libyaraNET;
using System;
using System.Collections.Generic;
using System.Text;


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

                    // Check for rule matches in process bytes
                    foreach (ScanResult result in results)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"Found {result.MatchingRule.Identifier}");
                        Console.ResetColor();

                        foreach (KeyValuePair<string, List<Match>> matches in result.Matches)
                        {
                            Console.WriteLine($"{matches.Key}");
                        }

                        if (result.MatchingRule.Identifier.Contains("meterpreter"))
                        {
                            // Check for C2 block and get offset if it exists
                            List<Match> matchList;
                            result.Matches.TryGetValue("$c2_block", out matchList);

                            if(matchList.Count > 0)
                            {                             
                                GetMeterpreterConfig(processBytes, matchList[0].Offset);
                            }
                        }
                        else if (result.MatchingRule.Identifier.Contains("CobaltStrike"))
                        {
                            // Check CobaltStrike version
                            List<Match> matchVersion3;
                            List<Match> matchVersion4;
                            result.Matches.TryGetValue("$config_v3", out matchVersion3);
                            result.Matches.TryGetValue("$config_v4", out matchVersion4);


                            if (matchVersion3.Count > 0)
                            {
                                ParseCobaltStrikeConfig.GetCobaltStrikeConfig(processBytes, matchVersion3[0].Offset, 3);
                            }
                            else if (matchVersion4.Count > 0)
                            {
                                ParseCobaltStrikeConfig.GetCobaltStrikeConfig(processBytes, matchVersion4[0].Offset, 4);
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Couldn't retrieve C2/Config information for {result.MatchingRule.Identifier}");
                        }
                    }
                }
                finally
                {
                    if (rules != null) rules.Dispose();
                }
            }
        }


        private static void GetMeterpreterConfig(byte[] processBytes, ulong c2BlockOffset)
        {
            Console.WriteLine("Retrieving Meterpreter C2...");

            // C2 information starts 42 bytes after beginning of C2 block
            byte[] tmp = new byte[512];
            Buffer.BlockCopy(processBytes, ((int)c2BlockOffset + 42), tmp, 0, 512);

            // Remove null bytes from unicode strings
            string c2String = Encoding.UTF8.GetString(tmp).Replace("\0", string.Empty);
            Console.WriteLine(c2String);
        }
    }
}