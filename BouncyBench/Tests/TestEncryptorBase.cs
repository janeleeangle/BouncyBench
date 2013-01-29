using CryptoTests.Ciphers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Tests
{
    public abstract class TestEncryptorBase
    {
        public abstract TestResult RunTest(byte[] key, byte[] IV, byte[] clearInput, int iterations = 1);
    }
}
