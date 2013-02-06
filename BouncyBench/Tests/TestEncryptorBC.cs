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

        public override TestResult RunTest(byte[] key, byte[] IV, byte[] clearInput, byte[] AddtnlAuthData, int iterations = 1)
        {
            int AddtnlAuthDataLength = 0;

            if (AddtnlAuthData != null)
                AddtnlAuthDataLength = AddtnlAuthData.Length;


            Stopwatch sw = new Stopwatch();
            byte[] encrypted = { };
            byte[] clearTextBack;
            TestResult tr = new TestResult();

            sw.Start();
            encCipher = new EncryptorBC<T>();

            for (int i = 0; i < iterations; i++)
            {
                // Init cipher here for more realistic iteration benchmark
                // of new IV per data to encrypt/decrypt
                encCipher.Init(key);

                // ENCRYPT
                encrypted = encCipher.Encrypt(clearInput, IV, AddtnlAuthData);

                //DECRYPT
                clearTextBack = encCipher.Decrypt(encrypted, IV.Length, AddtnlAuthDataLength);

                if (!clearTextBack.SequenceEqual(clearInput))
                    tr.passed = false;
            }
            sw.Stop();

            tr.overhead = ((encrypted.Length - clearInput.Length - AddtnlAuthDataLength) / (float)(clearInput.Length + AddtnlAuthDataLength));
            tr.name = encCipher.GetName();
            tr.time = new TimeSpan(sw.Elapsed.Ticks / iterations); // get average 
            tr.plainSizeBytes = clearInput.Length;
            tr.encryptSizeBytes = encrypted.Length;
            tr.AADSizeBytes = AddtnlAuthDataLength;

            TestResult.PrintResult(tr);

            return tr;
        }
    }
}
