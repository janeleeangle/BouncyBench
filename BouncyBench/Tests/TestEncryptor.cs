using Org.BouncyCastle.Crypto;
using CryptoTests.Ciphers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Tests
{
    class TestEncryptor<T> : TestEncryptorBase where T : IEncryptor, new() 
    {
        private T encCipher;

        public override TestResult RunTest(byte[] key, byte[] IV, byte[] clearInput, int iterations = 1)
        {
            Stopwatch sw = new Stopwatch();
            byte[] encrypted = { };
            byte[] clearTextBack;
            TestResult tr = new TestResult();

            sw.Start();
            encCipher = new T();
            for (int i = 0; i < iterations; i++)
            {                
                // Init cipher here for more realistic iteration benchmark
                // of new IV per data to encrypt/decrypt
                encCipher.Init(key);

                // ENCRYPT
                encrypted = encCipher.Encrypt(clearInput, IV);

                //DECRYPT
                if (IV!=null)
                    clearTextBack = encCipher.Decrypt(encrypted, IV.Length);
                else 
                    clearTextBack = encCipher.Decrypt(encrypted);

                if (!clearTextBack.SequenceEqual(clearInput))
                    tr.passed = false;
            }
            sw.Stop();

            tr.overhead = ((encrypted.Length - clearInput.Length) / (float)clearInput.Length);
            tr.name = encCipher.GetName();
            tr.time = new TimeSpan(sw.Elapsed.Ticks / iterations); // get average 
            tr.plainSizeBytes = clearInput.Length;
            tr.encryptSizeBytes = encrypted.Length;

            TestResult.PrintResult(tr);

            return tr;
        }
    }
}
