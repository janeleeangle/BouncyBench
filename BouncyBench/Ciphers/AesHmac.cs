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
            this.authKey = cryptoKey; // we're using the same key for the hmac tag
            aes = new CryptoTests.Ciphers.Aes();
            aes.Init(cryptoKey);
        }

        public byte[] Encrypt(byte[] secretMessage, byte[] iv = null, byte[] nonSecretPayload = null)
        {
            if (iv != null)
                throw new Exception("AesHmac generates IV internally, set IV to null in Init");

            // Decrypt the rest of the enc message
            var ivCipherText = aes.Encrypt(secretMessage);


            //Assemble encrypted message and add authentication
            using (var hmac = new HMACSHA256(authKey))
            using (var encryptedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(encryptedStream))
                {
                    //Write IV + Ciphertext
                    binaryWriter.Write(ivCipherText);
                    binaryWriter.Flush();

                    //Authenticate all data
                    var tag = hmac.ComputeHash(ivCipherText);
                    //Postpend tag
                    binaryWriter.Write(tag);
                }
                return encryptedStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] encryptedMessage, int IVLength=0, int nonSecretPayloadLength=0)
        {
            if (IVLength != 0)
                throw new Exception("Aes knows IVLength internally, remove or set IVLength to 0 in call");

            if (encryptedMessage == null)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            using (var hmac = new HMACSHA256(authKey))
            {
                var sentTag = new byte[hmac.HashSize / 8];
                //Calculate Tag
                var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentTag.Length);
                var ivLength = (BlockBitSize / 8);

                //if message length is to small just return null
                if (encryptedMessage.Length < sentTag.Length + nonSecretPayloadLength + ivLength)
                    return null;

                //Grab Sent Tag
                Array.Copy(encryptedMessage, encryptedMessage.Length - sentTag.Length, sentTag, 0, sentTag.Length);

                //Compare Tag with Constant time comparison
                var auth = true;
                for (var i = 0; i < sentTag.Length; i++)
                    auth = auth & sentTag[i] == calcTag[i]; //uses non-shortcircuit and (&)

                //if message doesn't authenticate return null
                if (!auth)
                    return null;

                // Decrypt the rest of the enc message
                long msgIvLen = encryptedMessage.Length - nonSecretPayloadLength - sentTag.Length;
                var encMsgNoHmac = new byte[msgIvLen];
                Array.Copy(encryptedMessage, encMsgNoHmac, msgIvLen);
                return aes.Decrypt(encMsgNoHmac);
            }
        }
    }
}
