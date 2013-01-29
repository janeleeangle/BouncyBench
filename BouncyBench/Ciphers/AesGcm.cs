using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoTests.Ciphers
{
    public  class AesGcm : IEncryptor
    {
        private readonly SecureRandom Random = new SecureRandom();

        private readonly int NonceBitSize = 128;
        private readonly int MacBitSize = 128;
        private byte[] aesKey;

        public string GetName()
        {
            string name;
            if (aesKey != null)
                name = String.Format("AES{0}-GCM", (aesKey.Length * 8));
            else
                name = String.Format("AES-GCM");
            return name;
        }

        public void Init(byte[] aesKey)
        {
            //User Error Checks
            if (aesKey == null)
                throw new ArgumentException("Key is null!");
            
            this.aesKey = aesKey;
        }

        public byte[] Encrypt(byte[] secretMessage, byte[] IV=null, byte[] nonSecretPayload = null)
        {
            if (IV != null)
                throw new Exception("AesGcm generates IV internally, set IV to null");

            if (secretMessage==null)
                throw new ArgumentException("Message to encrypt required", "secretMessage");

            //Non-secret Payload Optional
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            var plainText = secretMessage;

            //Using random nonce large enough not to repeat
            var nonce = new byte[NonceBitSize / 8];
            Random.NextBytes(nonce, 0, nonce.Length);

            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(new KeyParameter(aesKey), MacBitSize, nonce, nonSecretPayload);
            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            var cipherText = new byte[cipher.GetOutputSize(plainText.Length)];
            var len = cipher.ProcessBytes(plainText, 0, plainText.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Authenticated Payload
                    binaryWriter.Write(nonSecretPayload);
                    //Prepend Nonce
                    binaryWriter.Write(nonce);
                    //Write Cipher Text
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] encryptedMessage, int IVLength=0, int nonSecretPayloadLength = 0)
        {
            if (IVLength != 0)
                throw new Exception("AesGcm knows IVLength internally, remove or set IVLength to 0 in call");
            
            if (encryptedMessage == null)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            var messageArray = encryptedMessage;
            using (var cipherStream = new MemoryStream(messageArray))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                //Grab Payload
                var nonSecretPayload = cipherReader.ReadBytes(nonSecretPayloadLength);

                //Grab Nonce
                var nonce = cipherReader.ReadBytes(NonceBitSize / 8);

                var cipher = new GcmBlockCipher(new AesFastEngine());
                var parameters = new AeadParameters(new KeyParameter(aesKey), MacBitSize, nonce, nonSecretPayload);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(messageArray.Length - nonSecretPayloadLength - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);

                }
                catch (InvalidCipherTextException)
                {
                    //Return null if it doesn't authenticate
                    return null;
                }

                return plainText;
            }

        }
    }
}