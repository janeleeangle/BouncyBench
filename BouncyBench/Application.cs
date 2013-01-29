using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTests.Tests;
using CryptoTests.Ciphers;

namespace CryptoTests
{
    public class Application
    {
        private int size = 10;
        private int iterations = 100;

        public void Run()
        {
            bool ongoing = true;
            char option;

            // Warmup, to avoid one-time setup expenses
            Console.WriteLine("Performing a warmup run...");
            TestLoop(10, 1);

            //Run and display results on 1st start for user convenience
            PrintResults(TestLoop(size, iterations));

            while (ongoing)
            {
                option = PrintMenu();
                switch (option)
                {
                    case 'r':
                        PrintResults(TestLoop(size, iterations));
                        break;
                    case 'q':
                        ongoing = false;
                        break;
                    case 'c':
                        ChangeTestParams();
                        break;
                    default:
                        Console.WriteLine("Unknown input");
                        break;
                }
            }
        }

        private void ChangeTestParams()
        {
            string input = "";
            bool inputGood;
            do
            {
                Console.Write("Size is {0}. Enter new size:", size);
                input = Console.ReadLine();
                inputGood = int.TryParse(input, out size);
                if (!inputGood)
                    Console.WriteLine("Enter only a number");
            } while (!inputGood);

            do
            {
                Console.Write("Iterations are {0}. Enter new iteration:", iterations);
                input = Console.ReadLine();
                inputGood = int.TryParse(input, out iterations);
                if (!inputGood)
                    Console.WriteLine("Enter only a number");
            } while (!inputGood);
        }

        private char PrintMenu()
        {
            Console.WriteLine("R - Rerun tests");
            Console.WriteLine("C - Change size({0}) and iterations({1})", size, iterations);
            Console.WriteLine("Q - Quit");
            string input = Console.ReadLine().Replace(" ","").ToLowerInvariant();
            if (input.Length > 0)
                return input.ToCharArray()[0];
            else
                return 'r';
        }

        public List<TestResult> TestLoop(int size, int iter)
        {
            Random rng = new Random();
            var clearText = new byte[size];
            var key256 = new byte[32];
            var key192 = new byte[24];
            var key128 = new byte[16];
            var IV = new byte[16];
            for (long i = 0; i < clearText.LongLength; i++)
            {
                clearText[i] = Convert.ToByte(i % 256);
            }

            rng.NextBytes(key256);
            rng.NextBytes(key192);
            rng.NextBytes(key128);
            rng.NextBytes(IV);
            List<TestResult> results = new List<TestResult>();


            ///////////////////////////////////////////////
            // AES
            ///////////////////////////////////////////////
            results.Add(new TestEncryptor<Aes>().RunTest(key128, null, clearText, iter));
            results.Add(new TestEncryptor<Aes>().RunTest(key256, null, clearText, iter));

            ///////////////////////////////////////////////
            // AES + HMAC
            ///////////////////////////////////////////////
            results.Add(new TestEncryptor<AesHmac>().RunTest(key128, null, clearText, iter));
            results.Add(new TestEncryptor<AesHmac>().RunTest(key256, null, clearText, iter));

            /////////////////////////////////////////////////////////////
            // Bouncy Castle regular ciphers 
            ////////////////////////////////////////////////////////////
            results.Add(new TestEncryptorBC<AesFastEngine>().RunTest(key128, IV, clearText, iter));
            results.Add(new TestEncryptorBC<AesFastEngine>().RunTest(key256, IV, clearText, iter));

            /////////////////////////////////////////////////////////////
            // Bouncy Castle authenticated encryption ciphers
            ////////////////////////////////////////////////////////////
            results.Add(new TestEncryptor<AesGcm>().RunTest(key128, null, clearText, iter));
            results.Add(new TestEncryptor<AesGcm>().RunTest(key256, null, clearText, iter));

            return results;
        }

        private void PrintResults(List<TestResult> results)
        {
            Console.WriteLine("Benchmark test is : Encrypt=>Decrypt {0} bytes {1} times", size, iterations);
            Console.WriteLine();

            string format = "{0,-18}{1,10:F4}{2,16:N0}{3,16:N0}{4,11:P0}";
            Console.WriteLine(format, "Name", "time (ms)", "plain(bytes)", "encypted(bytes)", "overhead");

            foreach (var tr in results)
            {
                if (!tr.passed)
                    Console.WriteLine(Environment.NewLine + ">>> {0}: ERROR! Decrypting encrypted data doesn't return original information! <<<" + Environment.NewLine, tr.name);
                else
                {
                    Console.WriteLine(format, tr.name, tr.time.TotalMilliseconds, tr.plainSizeBytes, tr.encryptSizeBytes, tr.overhead);
                }
            }
            Console.WriteLine();

        }
    }
}
