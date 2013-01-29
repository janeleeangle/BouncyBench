using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Tests
{
    public class TestResult
    {
        public string name { get; set; }
        public int plainSizeBytes { get; set; }
        public int encryptSizeBytes { get; set; }
        public float overhead { get; set; }
        public TimeSpan time { get; set; }
        public bool passed { get; set; }

        private static string format = "{0,-18}{1,14:F4}{2,16:N0}{3,16:N0}{4,11:P0}";

        public TestResult()
        {
            passed = true;
        }

        public static void PrintResult(TestResult tr)
        {
            if (!tr.passed)
                Console.WriteLine(Environment.NewLine + ">>> {0}: ERROR! Decrypting encrypted data doesn't return original information! <<<" + Environment.NewLine, tr.name);
            else
            {
                Console.WriteLine(format, tr.name, tr.time.TotalMilliseconds, tr.plainSizeBytes, tr.encryptSizeBytes, tr.overhead);
            }
        }

        public static void PrintResults(List<TestResult> results, bool withHeader = true)
        {
            if (withHeader == true)
                PrintHeader();

            foreach (var tr in results)
            {
                PrintResult(tr);
            }

            Console.WriteLine();
        }

        public static void PrintHeader()
        {
            Console.WriteLine(format, "Name", "avg time (ms)", "plain(bytes)", "encypted(bytes)", "overhead");
        }
    }
}
