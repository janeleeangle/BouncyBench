using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTests.Ciphers;

namespace CryptoTests.Tests
{
    public class TestEncryptorBC<T> : TestEncryptorBase where T : IBlockCipher, new()
    {
        private EncryptorBC<T> encCipher;

        public override TestResult RunTest(byte[] key, byte[] IV, byte[] clearInput, int iterations = 1)
        {
            Stopwatch sw = new Stopwatch();
            byte[] encrypted = { };
            byte[] clearTextBack;
            TestResult tr = new TestResult();

            sw.Start();
            for (int i = 0; i < iterations; i++)
            {
                // Init cipher here for more realistic iteration benchmark
                // of new IV per data to encrypt/decrypt
                encCipher = new EncryptorBC<T>();
                encCipher.Init(key);

                // ENCRYPT
                encrypted = encCipher.Encrypt(clearInput, IV);

                //DECRYPT
                clearTextBack = encCipher.Decrypt(encrypted, IV.Length);

                if (!clearTextBack.SequenceEqual(clearInput))
                    tr.passed = false;
            }
            sw.Stop();

            tr.overhead = ((encrypted.Length - clearInput.Length) / (float)clearInput.Length);
            tr.name = encCipher.GetName();
            tr.time = sw.Elapsed;
            tr.plainSizeBytes = clearInput.Length;
            tr.encryptSizeBytes = encrypted.Length;

            return tr;
        }
    }
}
