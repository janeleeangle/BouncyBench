using System;
using System.IO;
using System.Text;
using Security.Cryptography;
using System.Security.Cryptography;
using Org.BouncyCastle.Utilities;

namespace CryptoTests.Ciphers
{
    public class AesGcmNet : IEncryptor
    {
        public int TagBitSize { get; set; }
        private readonly Random Random = new Random();

        // exact 96 is best for speed, no less, no more (larger kicks in extra hash cycles)
        // see The Galois/Counter Mode of Operation (GCM) paper by McGrew
        private int IVBitSize = 96;
        private byte[] aesKey;
        private byte[] IV;

        public AesGcmNet() { }

        public AesGcmNet(byte[] aesKey, byte[] IV = null)
        {
            this.Init(aesKey, IV);
        }

        // To maintain an interface compatible with BouncyBench
        public void Init(byte[] aesKey)
        {
            this.Init(aesKey, null);
        }

        public void Init(byte[] aesKey, byte[] IV)
        {
            // Key
            if ((aesKey.Length != 16) && (aesKey.Length != 24) && (aesKey.Length != 32))
                throw new ArgumentException("Key length not 128/192/256 bits.");

            if (!Arrays.AreEqual(aesKey, this.aesKey))
            {
                this.aesKey = aesKey;
            }

            // IV
            if (IV != null)
            {
                this.IV = IV;
                this.IVBitSize = IV.Length * 8;
            }
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

        public byte[] Encrypt(byte[] plainBytes, byte[] IV, byte[] AddtnlAuthData)
        {
            return Encrypt(plainBytes, AddtnlAuthData); // swallow IV 
        }

        // encrypted = LSByte [AddtnlAuthData || IV || cipherOnly || hmac ] MSByte
        public byte[] Encrypt(byte[] plainBytes, byte[] AddtnlAuthData)
        {
            if (plainBytes == null)
                return null;

            // Additional Authenticated (but NOT encrypted) Data
            AddtnlAuthData = AddtnlAuthData ?? new byte[] { };
            byte[] tag;
            byte[] cipherBytes;

            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                // Setup an authenticated chaining mode - The two current CNG options are
                // CngChainingMode.Gcm and CngChainingMode.Ccm.  This should be done before setting up
                // the other properties, since changing the chaining mode can update things such as the
                // valid and current tag sizes.
                aes.CngMode = CngChainingMode.Gcm;

                // Keys work the same as standard AES
                aes.Key = aesKey;

                // The IV (called the nonce in many of the authenticated algorithm specs) is not sized for
                // the input block size. Instead its size depends upon the algorithm.  12 bytes works
                // for both GCM and CCM. Generate a random 12 byte nonce here.
                if (this.IV == null)
                {
                    this.IV = new byte[IVBitSize / 8];
                    rng.GetBytes(this.IV);
                }

                aes.IV = this.IV;

                // Authenticated data becomes part of the authentication tag that is generated during
                // encryption, however it is not part of the ciphertext.  That is, when decrypting the
                // ciphertext the authenticated data will not be produced.  However, if the
                // authenticated data does not match at encryption and decryption time, the
                // authentication tag will not validate.
                aes.AuthenticatedData = AddtnlAuthData;

                // Perform the encryption - this works nearly the same as standard symmetric encryption,
                // however instead of using an ICryptoTransform we use an IAuthenticatedCryptoTrasform
                // which provides access to the authentication tag.
                using (MemoryStream ms = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    // Encrypt the secret message
                    cs.Write(plainBytes, 0, plainBytes.Length);

                    // Finish the encryption and get the output authentication tag and ciphertext
                    cs.FlushFinalBlock();
                    tag = encryptor.GetTag();
                    cipherBytes = ms.ToArray();
                }
            }

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Authenticated Payload
                    binaryWriter.Write(AddtnlAuthData);
                    //Prepend Nonce
                    binaryWriter.Write(this.IV);
                    //Write Cipher Text
                    binaryWriter.Write(cipherBytes);
                    //Write Tag
                    binaryWriter.Write(tag);
                }
                return combinedStream.ToArray();
            }
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

            byte[] cipherBytes;

            try
            {
                // incase of corruption in base64 format
                cipherBytes = Convert.FromBase64String(cipherText);
            }
            catch (FormatException ex)
            {
                //Logger.Exception(ex);
                return null;
            }

            var plainBytes = this.Decrypt(cipherBytes, AddtnlAuthDataLength);

            if (plainBytes == null)
                return null;
            return Encoding.UTF8.GetString(plainBytes);
        }

        // To maintain an interface compatible with BouncyBench
        public byte[] Decrypt(byte[] cipherBytes, int IVLength, int AddtnlAuthDataLength)
        {
            return Decrypt(cipherBytes, AddtnlAuthDataLength); // swallow IVLength !
        }

        public byte[] Decrypt(byte[] cipherBytes, int AddtnlAuthDataLength)
        {
            if (cipherBytes == null)
                return null;

            byte[] tag = new byte[TagBitSize / 8];

            try
            {

                using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
                {
                    using (var cipherReader = new BinaryReader(new MemoryStream(cipherBytes)))
                    {
                        aes.CngMode = CngChainingMode.Gcm;
                        aes.Key = aesKey;
                        //Read Additional Authenticated Data (AddtnlAuthData)
                        aes.AuthenticatedData = cipherReader.ReadBytes(AddtnlAuthDataLength);
                        aes.IV = cipherReader.ReadBytes(IVBitSize / 8);
                        // Tag lives at the end and it small, array copy it over
                        Array.Copy(cipherBytes, cipherBytes.Length - (TagBitSize / 8), tag, 0, (TagBitSize / 8));
                        aes.Tag = tag;
                    }

                    using (var ms = new MemoryStream())
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        int startOffset = AddtnlAuthDataLength + (IVBitSize / 8);
                        var length = cipherBytes.Length - AddtnlAuthDataLength - (IVBitSize / 8) - (TagBitSize / 8);

                        cs.Write(cipherBytes, startOffset, length);

                        // If the authentication tag does not match, we'll fail here with a
                        // CryptographicException, and the ciphertext will not be decrypted.
                        cs.FlushFinalBlock();

                        return ms.ToArray();
                    }
                }
            }

            catch (Exception ex)
            {
                //Logger.Exception(ex);
                if (ex is ArgumentException ||
                    ex is CryptographicException ||
                    ex is OverflowException)
                {
                    return null; // this is null here
                }
                else
                {
                    throw;
                }
            }
        }


        public string GetName()
        {
            if (aesKey == null)
                return "AES-GCM.NET";
            else
                return String.Format("AES{0}-GCM.NET", aesKey.Length * 8);
        }
    }
}