using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTests.Tests;
using CryptoTests.Ciphers;
using System.IO;

namespace CryptoTests
{
    public class Application
    {
        private int size = 100;
        private int iterations = 200;

        public void Run()
        {
            bool ongoing = true;
            char option;

            // Warmup, to avoid one-time setup expenses from skewing results
            Console.WriteLine("Performing a warmup run...");
            
            TextWriter tmp = Console.Out;
            Console.SetOut(new StringWriter()); //hide, it's gonna get ugly
            TestLoop(10, 1);
            Console.SetOut(tmp); // we want you back Console!

            //Run and display results on 1st start for user convenience
            TestLoop(size, iterations);

            while (ongoing)
            {
                option = PrintMenu();
                switch (option)
                {
                    case 'r':
                        TestLoop(size, iterations);
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
            size = GetNewNumber(size, "size");
            iterations = GetNewNumber(iterations, "iterations");
        }

        private int GetNewNumber(int currentVal, string label)
        {
            while (true)
            {
                Console.Write("Enter new {0}[{1}]:", label, currentVal);
                string input = Console.ReadLine();
                if (String.IsNullOrWhiteSpace(input))
                    return currentVal;
                else
                {
                    int newValue;
                    if (!int.TryParse(input, out newValue))
                        Console.WriteLine("Enter only a number");
                    else
                        return newValue;
                }
            } 
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

        public void TestLoop(int size, int iter)
        {
            Console.WriteLine("Benchmark test is : Encrypt=>Decrypt {0} bytes {1} times", size, iter);
            Console.WriteLine();
            TestResult.PrintHeader();

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

            ///////////////////////////////////////////////
            // AES
            ///////////////////////////////////////////////
             new TestEncryptor<Aes>().RunTest(key128, null, clearText, iter);
             new TestEncryptor<Aes>().RunTest(key256, null, clearText, iter);

            ///////////////////////////////////////////////
            // AES + HMAC
            ///////////////////////////////////////////////
             new TestEncryptor<AesHmac>().RunTest(key128, null, clearText, iter);
             new TestEncryptor<AesHmac>().RunTest(key256, null, clearText, iter);

            /////////////////////////////////////////////////////////////
            // Bouncy Castle regular ciphers 
            ////////////////////////////////////////////////////////////
            new TestEncryptorBC<AesFastEngine>().RunTest(key128, IV, clearText, iter);
            new TestEncryptorBC<AesFastEngine>().RunTest(key256, IV, clearText, iter);

            /////////////////////////////////////////////////////////////
            // Bouncy Castle authenticated encryption ciphers
            ////////////////////////////////////////////////////////////
            // Performance knobs:
            // 1. inside BouncyCastle/Crypto/Modes/GCMBlockCipher.cs, around line 58:
            //    m = new BasicGcmMultiplier();   <== fastest for small data (eg: 20 bytes)
            //    m = new Tables8kGcmMultiplier(); <== rather slow. Too many Array copies internally?
            //    m = new Tables64kGcmMultiplier(); <== slowest for small data / setup time overhead?
            // 2. inside BouncyBench/Ciphers/AesGcm.cs
            //    >> impact seen only when size < 10 bytes or so <<
            //    replace SecureRandom Random = new SecureRandom();  <== slow
            //    with    Random Random = new Random();             <== fast
            //    since GCM needs non-repeating IVs/counter, NOT crypto random IVs (like AES-CBC does) 
            new TestEncryptor<AesGcm>().RunTest(key128, null, clearText, iter);            
            new TestEncryptor<AesGcm>().RunTest(key256, null, clearText, iter);

            Console.WriteLine();
        }
    }
}
