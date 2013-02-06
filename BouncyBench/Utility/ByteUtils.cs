using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTests.Utility
{
    public static class ByteUtils
    {
        public static byte[] InitTo(byte[] input, byte value)
        {
            for (int i = 0; i < input.Length; i++)
            {
                input[i] = value;
            }
            return input;
        }

        public static byte[] InitTo(string hex)
        {
            int NumberChars = hex.Length / 2;
            byte[] bytes = new byte[NumberChars];
            StringReader sr = new StringReader(hex);
            for (int i = 0; i < NumberChars; i++)
            {
                var twoChars = new char[2] { (char)sr.Read(), (char)sr.Read() };
                bytes[i] = Convert.ToByte(new string(twoChars), 16);
            }
            sr.Dispose();
            return bytes;

            //byte[] result = new byte[value.Length / 2];
            //for (int i = 0; i < value.Length; i++)
            //{
            //    result[i] = Convert.ToByte(value[i]);
            //}
            //return result;
        }

        public static List<string> BytesArrayToStringList(byte[] input)
        {
            List<string> result = new List<string>();

            if (input == null)
            {
                result.Add(String.Format(">> null <<"));
                return result;
            }
            if (input.LongLength <= 0)
            {
                result.Add(String.Format(">> zero byte <<"));
                return result;
            }

            int bytesInRow = 128 / 8;
            int offset = 0;
            long remaining = input.LongLength;

            while (remaining > 0)
            {
                if (remaining >= bytesInRow)
                {
                    result.Add(BitConverter.ToString(input, offset, bytesInRow));
                    offset += bytesInRow;
                }
                else
                {
                    result.Add(BitConverter.ToString(input, offset, (int)remaining));
                    offset += (int)remaining;
                }
                remaining = remaining - bytesInRow;
            }
            return result;
        }

        public static void PrintByteArray(string name, byte[] p)
        {
            List<string> bytearray = BytesArrayToStringList(p);
            for (int i = 0; i < bytearray.Count; i++)
            {
                if (i == 0)
                    Console.WriteLine("{0,15} : {1}", name, bytearray[i]);
                else
                    Console.WriteLine("{0,15} : {1}", "", bytearray[i]);
            }
        }
    }
}
