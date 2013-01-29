using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Ciphers
{
    class AesIBlockCipher : IBlockCipher
    {
        public string AlgorithmName { get; private set; }
        public bool IsPartialBlockOkay { get; private set; }

        private bool forEncryption;
        private int BlockBitSize = 128;
        private byte[] IV;
        private byte[] key;

        //http://www.bouncycastle.org/docs/docs1.6/org/bouncycastle/crypto/BlockCipher.html
        public AesIBlockCipher()
        {
            AlgorithmName = "AesIBlockCipher";
            IsPartialBlockOkay = true;
        }

        public int GetBlockSize()
        {
            return BlockBitSize/8; // in bytes 
        }

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            IV = new byte[BlockBitSize / 8];
            rng.GetBytes(IV);

            key = ((KeyParameter)parameters).GetKey();
            if ( (key.Length != (128 / 8)) &&
                 (key.Length != (256 / 8))
                )
                throw new ArgumentException("Key should be 128 or 256 bits");
        }

        public int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            throw new NotImplementedException();
        }

        public void Reset()
        {
            throw new NotImplementedException();
        }

    }
}
