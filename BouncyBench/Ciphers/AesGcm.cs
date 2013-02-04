using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace CryptoTests.Ciphers
{
    public class AesGcm : IEncryptor
    {
        public int TagBitSize { get; private set; }

        private readonly Random Random = new Random();

        // TODO Make the expected input length available at construction, or perhaps allow changing multiplier on the fly
        private readonly GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new Tables8kGcmMultiplier());

        // exact 96 is best for speed, no less, no more (larger kicks in extra hash cycles)
        // see The Galois/Counter Mode of Operation (GCM) paper by McGrew
        private int IVBitSize = 96;
        private byte[] aesKey;
        private byte[] IV;

        private KeyParameter keyParameter;

        public void Init(byte[] aesKey)
        {
            this.Init(aesKey, null);
        }

        public string GetName()
        {
            if (aesKey == null)
                return "AES-GCM";
            else
                return String.Format("AES{0}-GCM", aesKey.Length * 8);
        }

        public void Init(byte[] aesKey, byte[] IV = null)
        {
            // Key
            if ((aesKey.Length != 16) && (aesKey.Length != 24) && (aesKey.Length != 32))
                throw new ArgumentException("Key length not 128/192/256 bits.");

            if (!Arrays.AreEqual(aesKey, this.aesKey))
            {
                this.aesKey = aesKey;
                this.keyParameter = new KeyParameter(aesKey);
            }

            // IV
            if (IV != null)
            {
                this.IV = IV;
                this.IVBitSize = IV.Length * 8;
            }

            // Tag size, 128 bit is recommended
            this.TagBitSize = 128;
        }

        /// <summary>
        /// Encrypts UTF8 string into Base64 string via AES256-GCM crypto
        /// </summary>
        /// <param name="plainText">UTF8 encoded string</param>
        /// <param name="AddtnlAuthData">UTF8 encoded Additional Authenticated Data. This is authenticated but NOT encrypted</param>
        /// <returns>Base64 string representing the encrypted bytes</returns>
        public string Encrypt(string plainText, string AddtnlAuthData = null)
        {
            if (String.IsNullOrEmpty(plainText))
                plainText = String.Empty;

            if (String.IsNullOrEmpty(AddtnlAuthData))
                AddtnlAuthData = String.Empty;

            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var AddtnlAuthDataBytes = Encoding.UTF8.GetBytes(AddtnlAuthData);

            var cipherBytes = this.Encrypt(plainBytes, AddtnlAuthDataBytes);

            return Convert.ToBase64String(cipherBytes);
        }

        public byte[] Encrypt(byte[] plainBytes, byte[] AddtnlAuthData)
        {
            if (plainBytes == null)
                return null;

            // Additional Authenticated (but NOT encrypted) Data
            AddtnlAuthData = AddtnlAuthData ?? new byte[] { };

            // IV prep
            if (this.IV == null)
            {
                this.IV = new byte[IVBitSize / 8];
                Random.NextBytes(this.IV);
            }

            var parameters = new AeadParameters(keyParameter, TagBitSize, IV, AddtnlAuthData);
            keyParameter = null;

            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            var cipherBytes = new byte[cipher.GetOutputSize(plainBytes.Length)];
            var len = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, cipherBytes, 0);
            cipher.DoFinal(cipherBytes, len);

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Authenticated Payload
                    binaryWriter.Write(AddtnlAuthData);
                    //Prepend Nonce
                    binaryWriter.Write(IV);
                    //Write Cipher Text
                    binaryWriter.Write(cipherBytes);
                }
                return combinedStream.ToArray();
            }
        }

        public byte[] Encrypt(byte[] plainBytes, byte[] IV, byte[] AddtnlAuthData)
        {
            return Encrypt(plainBytes, AddtnlAuthData); // swallow IV 
        }

        /// <summary>
        /// Decrypts the Base64 encoded encrypted string
        /// </summary>
        /// <param name="cipherText">Base64 string representing the encrypted bytes</param>
        /// <param name="AddtnlAuthDataLength"></param>
        /// <returns>Decrypted UTF8 string</returns>
        public string Decrypt(string cipherText, int AddtnlAuthDataLength = 0)
        {
            if (String.IsNullOrEmpty(cipherText))
                cipherText = String.Empty;

            var cipherBytes = Convert.FromBase64String(cipherText);

            var plainBytes = this.Decrypt(cipherBytes, AddtnlAuthDataLength);

            return Encoding.UTF8.GetString(plainBytes);
        }

        public byte[] Decrypt(byte[] cipherBytes, int AddtnlAuthDataLength)
        {
            if (cipherBytes == null)
                return null;

            using (var cipherStream = new MemoryStream(cipherBytes))
            {
                using (var cipherReader = new BinaryReader(cipherStream))
                {
                    //Read Additional Authenticated Data (AAD)
                    var AddtnlAuthData = cipherReader.ReadBytes(AddtnlAuthDataLength);

                    // Read out IV
                    var IV = cipherReader.ReadBytes(IVBitSize / 8);

                    // Format AEAD parameters 
                    var parameters = new AeadParameters(keyParameter, TagBitSize, IV, AddtnlAuthData);
                    keyParameter = null;

                    cipher.Init(false, parameters);

                    // Read in cipher text, create output buffer
                    var encryptedBytes = cipherReader.ReadBytes(cipherBytes.Length - AddtnlAuthDataLength - IV.Length);
                    var clearBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];

                    // Decrypt ciphertext while verifying tag
                    try
                    {
                        var len = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, clearBytes, 0);
                        cipher.DoFinal(clearBytes, len);
                    }
                    catch (InvalidCipherTextException)
                    {
                        //Return null if it doesn't authenticate
                        //Log(...);
                        throw;
                    }

                    return clearBytes;
                }
            }
        }

        public byte[] Decrypt(byte[] cipherBytes, int IVLength, int AddtnlAuthDataLength)
        {
            return Decrypt(cipherBytes, AddtnlAuthDataLength); // swallow IVLength !
        }

        private IGcmMultiplier ChooseMultiplier(long p)
        {
            // Peter's latest update on  makes this pointless
            // as 8k performance is very very good
            //// Based on some quick tests in 01/29/2013
            //if (p < 30)
            //    return new BasicGcmMultiplier();
            //if (p > 500000)
            //    return new Tables64kGcmMultiplier();

            // this is a great default otherwise
            return new Tables8kGcmMultiplier();
        }
    }
}