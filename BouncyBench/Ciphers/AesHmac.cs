using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Ciphers
{
    public class AesHmac : IEncryptor
    {
        private readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

        //Preconfigured Encryption Parameters
        private readonly int BlockBitSize = 128;
        private byte[] cryptoKey;
        private byte[] authKey;
        private CryptoTests.Ciphers.Aes aes;

        public string GetName()
        {
            string name;
            if (cryptoKey!=null)
                name = String.Format("AES{0}-HMACSHA256", (cryptoKey.Length * 8));
            else
                name = String.Format("AES-HMACSHA256");
            return name;
        }

        public void Init(byte[] cryptoKey)
        {

            this.cryptoKey = cryptoKey;
            this.authKey = cryptoKey; // we're using the same key for the hmac hmac
            aes = new CryptoTests.Ciphers.Aes();
            aes.Init(cryptoKey);
        }

        // encrypted = LSByte [ AddtnlAuthData || IV || cipher || hmac ] MSByte
        public byte[] Encrypt(byte[] secretMessage, byte[] iv = null, byte[] AddtnlAuthData = null)
        {
            if (iv != null)
                throw new Exception("AesHmac generates IV internally, set IV to null in Init");

            //Assemble encrypted message and add authentication
            using (var hmacSha256 = new HMACSHA256(authKey))
            using (var encryptedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(encryptedStream))
                {
                    // Encrypt message using AES
                    var ivCipherText = aes.Encrypt(secretMessage, iv, AddtnlAuthData);

                    //Write IV + Ciphertext
                    binaryWriter.Write(ivCipherText);
                    binaryWriter.Flush();

                    //Authenticate all data
                    var hmac = hmacSha256.ComputeHash(ivCipherText);
                    //Postpend hmac
                    binaryWriter.Write(hmac);
                }
                return encryptedStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] encryptedMessage, int IVLength=0, int AddtnlAuthDataLength=0)
        {
            if (IVLength != 0)
                throw new Exception("Aes knows IVLength internally, remove or set IVLength to 0 in call");

            if (encryptedMessage == null)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            using (var hmac = new HMACSHA256(authKey))
            {
                //if message length is to small just return null
                var ivLength = (BlockBitSize / 8);
                var sentHmac = new byte[hmac.HashSize / 8];
                if (encryptedMessage.Length < sentHmac.Length + AddtnlAuthDataLength + ivLength)
                    return null;

                // 1. Authenticate data
                var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentHmac.Length);
                //    Grab Sent hmac
                Array.Copy(encryptedMessage, encryptedMessage.Length - sentHmac.Length, sentHmac, 0, sentHmac.Length);
                //    Compare hmac with Constant time comparison
                var auth = true;
                for (var i = 0; i < sentHmac.Length; i++)
                    auth = auth & sentHmac[i] == calcTag[i]; //uses non-shortcircuit and (&)
                //    if message doesn't authenticate return null
                if (!auth)
                    return null;

                // 2. Decrypt encrypted message after stripping off HMAC
                // encrypted = LSByte [ AddtnlAuthData || IV || cipher || hmac ] MSByte
                long msgIvLen = encryptedMessage.Length - sentHmac.Length;
                var encMsgNoHmac = new byte[msgIvLen];
                Array.Copy(encryptedMessage, encMsgNoHmac, msgIvLen);
                return aes.Decrypt(encMsgNoHmac, 0, AddtnlAuthDataLength);
            }
        }
    }
}
