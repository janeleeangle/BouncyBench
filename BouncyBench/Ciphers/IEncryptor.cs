using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Ciphers
{
    interface IEncryptor
    {
        string GetName();

        void Init(byte[] cryptoKey);

        byte[] Encrypt(byte[] plain, byte[] iv = null, byte[] nonSecretPayload = null);

        byte[] Decrypt(byte[] cipher, int IVLength=0, int nonSecretPayloadLength = 0);
    }
}
