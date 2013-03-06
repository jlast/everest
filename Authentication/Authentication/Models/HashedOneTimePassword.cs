using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Models
{
    public class HashedOneTimePassword
    {
        public static string GeneratePassword(string secret, long iterationNumber, int digits = 6)
        {
            byte[] counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            byte[] key = Encoding.ASCII.GetBytes(secret);

            HMACSHA1 hmac = new HMACSHA1(key, true);

            byte[] hash = hmac.ComputeHash(counter);

            int offset = hash[hash.Length - 1] & 0xf;

            int binary =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

            int password = binary % (int)Math.Pow(10, digits); // 6 digits

            return password.ToString(new string('0', digits));
        }

        public static readonly DateTime UNIX_EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static string GetPassword(string secret)
        {
            long counter = (long)(DateTime.UtcNow - UNIX_EPOCH).TotalSeconds / 30;

            return GeneratePassword(secret, counter);
        }

        public static bool IsValid(string secret, string password, int checkAdjacentIntervals = 1)
        {
            if (password == GetPassword(secret))
                return true;

            /*for (int i = 1; i <= checkAdjacentIntervals; i++)
            {
                if (password == GetPassword(secret, GetCurrentCounter() + i))
                    return true;

                if (password == GetPassword(secret, GetCurrentCounter() - i))
                    return true;
            }*/

            return false;
        }
    }
}