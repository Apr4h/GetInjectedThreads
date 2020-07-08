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
                    "$v1 = { 73 70 72 6E 67 00} " +
                    "$v2 = { 69 69 69 69 69 69 69 69} " +
                "condition: $v1 and $v2}";

        public static List<string> meterpreterRules = new List<string>(new string[] {
            
          
            "rule meterpreter_reverse_tcp_shellcode { " +
                "strings:  " +
                    "$s1 = { fce8 8?00 0000 60 } " +    // shellcode prologe in metasploit
                    "$s2 = { 648b ??30 } " +            // mov edx, fs:[???+0x30]
                    "$s3 = { 4c77 2607 } " +            // kernel32 checksum
                    "$s4 = ws2_ " +                     // ws2_32.dll
                    "$s5 = { 2980 6b00 } " +            // WSAStartUp checksum
                    "$s6 = { ea0f dfe0 } " +            // WSASocket checksum
                    "$s7 = { 99a5 7461 } " +            // connect checksum
                "condition: " +
                    "all of them and filesize < 5KB}",


            "rule  meterpreter_reverse_tcp_shellcode_rev1 { " +
                    "strings:  " +
                        "$s1 = { 6a00 53ff d5 } " +
                    "condition: meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)}",


            "rule  meterpreter_reverse_tcp_shellcode_rev2 { " +
                    "strings:  " +
                        "$s1 = { 75ec c3 } " +
                    "condition: meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)}",


            "rule  meterpreter_reverse_tcp_shellcode_domain { " +
                    "strings:  " +
                        "$s1 = { a928 3480 } " +             // Checksum for gethostbyname
                        "$domain = /(\\w+\\.)+\\w{2,6}/" +
                    "condition: meterpreter_reverse_tcp_shellcode and all of them}"
        });
    }
}
