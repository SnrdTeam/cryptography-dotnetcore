using Adeptik.Cryptography.Algorithms;
using System;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Adeptik.Cryptography.Converters
{
    /// <summary>
    /// Converts <see cref="BigInteger"/> from <see cref="string"/>, containing checksum of data.
    /// <para>
    /// The original input string is a <see cref="BigInteger"/>, call it original number.
    /// This value contains checksum in least significant bits in the amount corresponding to the hash size of the hashing algorithm used.
    /// The remaining bits form the payload. The sign of the payload corresponds to the sign of the original number.
    /// </para>
    /// <para>
    /// When calculating the hash, сonversion of the payload into a byte array is performed for the its absolute value in little-endian order without trailing zeroes.
    /// </para>
    /// <para>
    /// When converting a hash to a number, its byte array is treated as a non-negative number in little-endian order.
    /// </para>
    /// </summary>
    public class RedundantBigIntegerConverter : BigIntegerTypeConverter
    {
        /// <summary>
        /// Static constructor.
        /// </summary>
        static RedundantBigIntegerConverter()
        {
            CryptoConfig.AddAlgorithm(typeof(Adler32), "Adler-32");
        }

        /// <inheritdoc />
        /// <exception cref="InvalidOperationException">Hash algorithm is not applicable due to its hash size is 0.</exception>
        /// <exception cref="FormatException">Checksum verification failed.</exception>
        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
        {
            const string hashAlgorithmName = "Adler-32";
            var bigInt = (BigInteger)base.ConvertFrom(context, culture, value);
            var isNegative = bigInt.Sign < 0;
            if (isNegative) bigInt = BigInteger.Negate(bigInt);
            using var hashAlgorithm = HashAlgorithm.Create(hashAlgorithmName);
            if (hashAlgorithm.HashSize <= 0)
            {
                throw new InvalidOperationException($"Hash algorithm {hashAlgorithmName} with {hashAlgorithm.HashSize} hash size is not applicable.");
            }
            var checksumDivider = BigInteger.Pow(0b10, hashAlgorithm.HashSize);
            var payload = bigInt / checksumDivider;
            var checksum = bigInt % checksumDivider;

            var payloadBytes = payload.ToByteArray(isUnsigned: true, isBigEndian: false);
            var payloadHashBytes = hashAlgorithm.ComputeHash(payloadBytes);
            var payloadHash = new BigInteger(payloadHashBytes.AsSpan(), isUnsigned: true, isBigEndian: false);

            if (payloadHash != checksum)
            {
                throw new FormatException("Value is not valid due to its checksum verification failed.");
            }
            return payload * (isNegative ? -1 : 1);
        }
    }
}
