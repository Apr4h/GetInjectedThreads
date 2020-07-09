using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace GetInjectedThreads.Yara
{
    static class YaraRules
    {

        public static string cobaltStrikeRule = "rule CobaltStrike { " +      
                "strings:  " +
                    "$s1 = { 73 70 72 6E 67 00} " +
                    "$s2 = { 69 69 69 69 69 69 69 69} " +
                "condition: $v1 and $v2" +
            "}";

        public static List<string> meterpreterRules = new List<string>(new string[] {

            "rule Meterpreter_ {" +
                "strings: " +
                    "$s1 = { 57 53 32 5f 33 32 } " +        // WS2_32
                    "$s2 = { 6d 65 74 73 72 76 } " +        // metsrv     
                    "$thing = {  } " +        
                "condition: all of them" +
            "}"
        }); 
    }
}
