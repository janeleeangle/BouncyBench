using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTests.Ciphers;

namespace CryptoTests.Ciphers
{
    public sealed class EncryptorBC<T> : IEncryptor where T : IBlockCipher, new() 
    {
        private Encoding encoding;

        private IBlockCipher blockCipher;

        private BufferedBlockCipher cipher;

        private ICipherParameters parameters;

        private byte[] IV;
        private byte[] key;

        public void Init(byte[] key)
        {
            this.key = key;
        }

        public string GetName()
        {
            return cipher.AlgorithmName;
        }

        public byte[] Encrypt(byte[] plain, byte[]IV=null, byte[] nonSecretPayload=null)
        {
            // Setup
            this.blockCipher = new CbcBlockCipher(new T());
            if (IV == null)
            {
                this.IV = null;
                this.parameters = new KeyParameter(key);
            }
            else
            {
               this.IV = IV;     
               this.parameters = new ParametersWithIV(new KeyParameter(key), IV);
            }
            this.cipher = new BufferedBlockCipher(this.blockCipher);
            this.encoding = Encoding.UTF8;

            // Add padding
            plain = AddPad(plain);

            // Get cipher text i.e. do actual encryption
            byte[] cipher = this.BouncyCastleCrypto(true, plain);

            // Format for output i.e.
            // encrypted = nonSecretPayload || IV || ciphertext
            long sizeEncrypted = 0;
            long offset = 0;
                        
            if (nonSecretPayload!=null)
                sizeEncrypted += nonSecretPayload.LongLength;

            if (IV != null)
                sizeEncrypted += IV.Length;
            
            sizeEncrypted += cipher.LongLength;
            byte[] encrypted = new byte[sizeEncrypted];

            if (nonSecretPayload != null)
            {
                Array.Copy(nonSecretPayload, 0, encrypted, offset, nonSecretPayload.LongLength);
                offset += nonSecretPayload.LongLength;
            }

            if (IV != null)
            {
                Array.Copy(IV, 0, encrypted, offset, IV.Length);
                offset += IV.Length;
            }

            Array.Copy(cipher, 0, encrypted, offset, cipher.LongLength);

            return encrypted;
        }

        public byte[] Decrypt(byte[] encInput, int IVlength=0, int nonSecretPayloadLength=0)
        {
            // Format for output i.e.
            // encInput = nonSecretPayload || IV || ciphertext
            // Get IV
            if (IVlength>0)
                Array.Copy(encInput, nonSecretPayloadLength, IV, 0, IVlength);
            
            // Get Cipher
            long cipherLength = encInput.LongLength - IVlength - nonSecretPayloadLength;
            byte[] cipher = new byte[cipherLength];
            Array.Copy(encInput, nonSecretPayloadLength + IVlength, cipher, 0, cipherLength);

            // Setup
            this.blockCipher = new CbcBlockCipher(new T());
            if (IV == null)
            {
                this.parameters = new KeyParameter(key);
            }
            else
            {
                this.parameters = new ParametersWithIV(new KeyParameter(key), IV);
            }

            this.cipher = new BufferedBlockCipher(this.blockCipher);
            this.encoding = Encoding.UTF8;

            // Do actual decryption
            byte[] clearPadded = this.BouncyCastleCrypto(false, cipher);

            // strip off 
            return RemovePad(clearPadded);
        }

        private byte[] BouncyCastleCrypto(bool forEncrypt, byte[] input)
        {
            try
            {
                this.cipher.Init(forEncrypt, this.parameters);

                return this.cipher.DoFinal(input);
            }
            catch (CryptoException)
            {
                throw;
            }
        }

        // Per PaddingMode.PKCS7
        private byte[] AddPad(byte[] plain)
        {
            int cipherBlockSizeInBytes = this.blockCipher.GetBlockSize();
            int remainingByteSize = plain.Length % cipherBlockSizeInBytes;
            int paddingSizeInBytes = cipherBlockSizeInBytes - remainingByteSize;

            if (remainingByteSize == 0)
                paddingSizeInBytes = this.blockCipher.GetBlockSize();

            // Per PKCS7, each byte itself suggests how many bytes of padding there are
            // if 0 an entire block is added
            byte[] padByte = BitConverter.GetBytes(paddingSizeInBytes);

            // Copy existing data to dest buffer
            byte[] paddedPlain = new byte[plain.Length + paddingSizeInBytes];
            Array.Copy(plain, paddedPlain, plain.Length);

            // Copy over padding bytes at end
            for (int i = plain.Length; i < plain.Length + paddingSizeInBytes; i++)
            {
                paddedPlain[i] = padByte[0];
            }

            return paddedPlain;
        }

        // Per PaddingMode.PKCS7
        private byte[] RemovePad(byte[] cipher)
        {
            byte lastByte = cipher[cipher.Length - 1];
            int paddingSizeInBytes = Convert.ToInt32(lastByte);

            // Copy existing data to dest buffer
            byte[] unpaddedCipher = new byte[cipher.Length - paddingSizeInBytes];
            Array.Copy(cipher, unpaddedCipher, cipher.Length - paddingSizeInBytes);

            return unpaddedCipher;
        }

    }
}
