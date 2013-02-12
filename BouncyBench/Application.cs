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
        private int bytesToEncrypt = 100;
        private int AADbytesLength = 20;
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
            TestLoop(bytesToEncrypt, iterations);

            while (ongoing)
            {
                option = PrintMenu();
                switch (option)
                {
                    case 'r':
                        TestLoop(bytesToEncrypt, iterations);
                        break;
                    case 'q':
                        ongoing = false;
                        break;
                    case 'c':
                        ChangeTestParams();
                        break;
                    case 's':
                        TestSizes();
                        break;
                    default:
                        Console.WriteLine("Unknown input");
                        break;
                }
            }
        }

        private void ChangeTestParams()
        {
            bytesToEncrypt = GetNewNumber(bytesToEncrypt, "number of bytes to encrypt");
            AADbytesLength = GetNewNumber(AADbytesLength, "number of bytes of unencrypted but authenticated data");
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
            Console.WriteLine("C - Change bytes to encrypt({0}), AAD size({1}) or iterations({2})", bytesToEncrypt, AADbytesLength, iterations);
            Console.WriteLine("S - Size testing different input lengths");
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

            var AddtnlAuthData = new byte[AADbytesLength];
            Utility.ByteUtils.InitTo(AddtnlAuthData, 0xbe);

            ///////////////////////////////////////////////
            // AES
            ///////////////////////////////////////////////
            new TestEncryptor<Aes>().RunTest(key128, null, clearText, AddtnlAuthData, iter);
            new TestEncryptor<Aes>().RunTest(key256, null, clearText, AddtnlAuthData, iter);

            ///////////////////////////////////////////////
            // AES + HMAC
            ///////////////////////////////////////////////
            new TestEncryptor<AesHmac>().RunTest(key128, null, clearText, AddtnlAuthData, iter);
            new TestEncryptor<AesHmac>().RunTest(key256, null, clearText, AddtnlAuthData, iter);

            /////////////////////////////////////////////////////////////
            // AES-GCM .NET Security.Cryptography.dll  authenticated encryption ciphers
            ////////////////////////////////////////////////////////////
            new TestEncryptor<AesGcmNet>().RunTest(key128, null, clearText, AddtnlAuthData, iter);
            new TestEncryptor<AesGcmNet>().RunTest(key256, null, clearText, AddtnlAuthData, iter);

            /////////////////////////////////////////////////////////////
            // Bouncy Castle regular ciphers 
            ////////////////////////////////////////////////////////////            
            new TestEncryptorBC<AesFastEngine>().RunTest(key128, IV, clearText, AddtnlAuthData, iter);
            new TestEncryptorBC<AesFastEngine>().RunTest(key256, IV, clearText, AddtnlAuthData, iter);
            new TestEncryptorBC<RC6Engine>().RunTest(key256, IV, clearText, AddtnlAuthData, iter);
            new TestEncryptorBC<TwofishEngine>().RunTest(key256, IV, clearText, AddtnlAuthData, iter);            

            /////////////////////////////////////////////////////////////
            // Bouncy Castle authenticated encryption ciphers
            ////////////////////////////////////////////////////////////
            new TestEncryptor<AesGcm>().RunTest(key128, null, clearText, AddtnlAuthData, iter);
            new TestEncryptor<AesGcm>().RunTest(key256, null, clearText, AddtnlAuthData, iter);
            
            TestResult.PrintFooter();
            Console.WriteLine();
        }

        public void TestSizes()
        {
            Console.WriteLine("Benchmark test is SIZE. Encrypt=>Decrypt");
            Console.WriteLine();
            TestResult.PrintHeader();

            var AddtnlAuthData = new byte[AADbytesLength];
            Utility.ByteUtils.InitTo(AddtnlAuthData, 0xbe);

            Random rng = new Random();
            var key256 = new byte[32];
            var IV = new byte[16];

            rng.NextBytes(key256);
            rng.NextBytes(IV);

            int[] sizes = { 1, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000 };

            foreach (int currentSize in sizes)
            {
                var clearText = new byte[currentSize];
                for (long i = 0; i < clearText.LongLength; i++)
                {
                    clearText[i] = Convert.ToByte(i % 256);
                }
                new TestEncryptor<AesGcm>().RunTest(key256, null, clearText, AddtnlAuthData, 1);
            }

            TestResult.PrintFooter();
        }
    }
}
