using System;
using System.Security.Cryptography;
namespace GenerateApiKey
{
    public class Program
    {
        public static void Main(string[] args)
        {
            using (var cryptoProvider = RandomNumberGenerator.Create())
            {
                var secretKeyByteArray = new byte[32];//256 bit
                cryptoProvider.GetBytes(secretKeyByteArray);
                Convert.ToBase64String(secretKeyByteArray);
            }
        }
    }
}
