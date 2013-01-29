using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Ciphers
{
    public class Aes : IEncryptor
    {
        private readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

        private int BlockBitSize = 128;
        private byte[] aesKey;

        public string GetName()
        {
            string name;
            if (aesKey != null)
                name = String.Format("AES{0}", (aesKey.Length * 8));
            else
                name = String.Format("AES");
            return name;
        }

        public void Init(byte[] cryptoKey)
        {
            this.aesKey = cryptoKey;
        }

        public byte[] Encrypt(byte[] secretMessage, byte[] iv = null, byte[] nonSecretPayload = null)
        {
            if (iv != null)
                throw new Exception("Aes generates IV internally, set IV to null");
            
            if (secretMessage == null)
                throw new ArgumentException("Secret Message Required!", "secretMessage");

            //non-secret payload optional
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            byte[] cipherText;
            byte[] IV;

            using (var aes = new AesManaged
            {
                KeySize = (aesKey.Length*8),
                BlockSize = BlockBitSize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {

                ////Use random IV
                //aes.GenerateIV();
                IV = aes.IV;

                using (var encrypter = aes.CreateEncryptor(aesKey, aes.IV))
                using (var cipherStream = new MemoryStream())
                {
                    using (var tCryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                    using (var tBinaryWriter = new BinaryWriter(tCryptoStream))
                    {
                        //Encrypt Data
                        tBinaryWriter.Write(secretMessage);
                    }

                    cipherText = cipherStream.ToArray();
                }
            }

            //Assemble encrypted message + IV
            using (var encryptedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(encryptedStream))
                {
                    //Prepend non-secret payload if any
                    binaryWriter.Write(nonSecretPayload);
                    //Prepend IV
                    binaryWriter.Write(IV);
                    //Write Ciphertext
                    binaryWriter.Write(cipherText);
                    binaryWriter.Flush();
                }
                return encryptedStream.ToArray();
            }
        }

        public byte[] Decrypt(byte[] message, int IVLength=0, int nonSecretPayloadLength = 0)
        {
            if (IVLength != 0)
                throw new Exception("Aes knows IVLength internally, remove or set IVLength to 0 in call");
            
            if (message == null)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            using (var aes = new AesManaged
            {
                KeySize = (aesKey.Length * 8),
                BlockSize = BlockBitSize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {
                var ivLength = (BlockBitSize / 8);

                //Grab IV from message
                var iv = new byte[ivLength];
                Array.Copy(message, nonSecretPayloadLength, iv, 0, iv.Length);

                using (var decrypter = aes.CreateDecryptor(aesKey, iv))
                using (var plainTextStream = new MemoryStream())
                {
                    using (var decrypterStream = new CryptoStream(plainTextStream, decrypter, CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(decrypterStream))
                    {
                        //Decrypt Cipher Text from Message
                        binaryWriter.Write(
                            message,
                            nonSecretPayloadLength + iv.Length,
                            message.Length - nonSecretPayloadLength - iv.Length
                        );
                    }
                    //Return Plain Text
                    return plainTextStream.ToArray();
                }
            }
        } // end of Decrypt
    }
}
