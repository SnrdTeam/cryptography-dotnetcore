using System;
using System.Security.Cryptography;

namespace Adeptik.Cryptography.Algorithms
{
    /// <summary>
    /// Class implements Adler32 checksum algirithm
    /// <see href="https://tools.ietf.org/html/rfc1950#section-9"/>
    /// </summary>
    public class Adler32 : HashAlgorithm
    {
        private uint _hashValue = 1;

        /// <summary>
        /// Method registers Adler-32 algorihm using CryptoConfig 
        /// if algorithm with such name not already register
        /// </summary>
        public static void EnsureRegistered()
        {
            using var algorithm = (IDisposable)CryptoConfig.CreateFromName("Adler-32");
            if (algorithm == null)
                CryptoConfig.AddAlgorithm(typeof(Adler32), "Adler-32");
        }
        /// <inheritdoc />
        public override void Initialize()
        {
            _hashValue = 1;
        }

        /// <inheritdoc />
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            const uint BASE = 65521;
            uint s1 = _hashValue & 0xffff;
            uint s2 = (_hashValue >> 16) & 0xffff;

            for (int n = 0; n < cbSize; n++)
            {
                s1 = (s1 + array[ibStart + n]) % BASE;
                s2 = (s2 + s1) % BASE;
            }

            _hashValue = (s2 << 16) + s1;
        }

        /// <inheritdoc />
        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(_hashValue);
        }

        /// <inheritdoc />
        public override int HashSize => 32;
    }
}
