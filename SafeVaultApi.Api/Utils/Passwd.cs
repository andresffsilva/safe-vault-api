using System.Security.Cryptography;
using System.Text;

namespace SafeVaultApi.Api.Utils
{
    public static class Passwd
    {
        private const int WorkFactor = 12;
        private const int MaxLength = 16;
        public static string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
        }
        public static bool VerifyPassword(string password, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }
        public static string GenerateRandomPassphrase()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*_.";
            StringBuilder passphrase = new StringBuilder(MaxLength);

            byte[] byteBuffer = new byte[MaxLength];

            RandomNumberGenerator.Fill(byteBuffer);

            for (int i = 0; i < MaxLength; i++)
            {
                passphrase.Append(chars[byteBuffer[i] % chars.Length]);
            }

            return passphrase.ToString();
        }
    }
}