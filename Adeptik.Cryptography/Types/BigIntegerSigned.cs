using Adeptik.Cryptography.Converters;
using System;
using System.ComponentModel;
using System.Numerics;
using System.Security.Cryptography;

namespace Adeptik.Cryptography.Types
{
    /// <summary>
    /// A <see cref="BigInteger"/> value with digest.
    /// </summary>
    [TypeConverter(typeof(BigIntegerSignedConverter))]
    public class BigIntegerSigned
    {
        /// <summary>
        /// Creates a new instance of <see cref="BigIntegerSigned"/>
        /// </summary>
        /// <param name="payload">A <see cref="BigInteger"/> value.</param>
        public BigIntegerSigned(BigInteger payload)
        {
            Payload = payload;
        }

        /// <summary>
        /// A <see cref="BigInteger"/> value.
        /// </summary>
        public BigInteger Payload { get; }

        /// <summary>
        /// Calculates digest of absolute value of the <see cref="Payload"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When calculating the hash, сonversion of the payload into a byte array is performed for the its absolute value in little-endian order without trailing zeroes.
        /// </para>
        /// <para>
        /// When converting a hash to a number, its byte array is treated as a non-negative number in little-endian order.
        /// </para>
        /// </remarks>
        /// <param name="hashAlgorithmName">A hash algorithm name used to calculate hash value of the <see cref="Payload"/>.</param>
        /// <returns>Digest value.</returns>
        public BigInteger GetDigest(string hashAlgorithmName)
        {
            using var hashAlgorithm = HashAlgorithm.Create(hashAlgorithmName);
            if (hashAlgorithm.HashSize <= 0)
            {
                throw new InvalidOperationException($"Hash algorithm {hashAlgorithmName} with {hashAlgorithm.HashSize} hash size is not applicable.");
            }
            var checksumDivider = BigInteger.Pow(0b10, hashAlgorithm.HashSize);

            var isNegative = Payload.Sign < 0;
            var absolutePayload = isNegative ? BigInteger.Negate(Payload) : Payload;

            var payloadBytes = absolutePayload.ToByteArray(isUnsigned: true, isBigEndian: false);
            var payloadHashBytes = hashAlgorithm.ComputeHash(payloadBytes);
            var payloadHash = new BigInteger(payloadHashBytes.AsSpan(), isUnsigned: true, isBigEndian: false);

            return payloadHash;
        }
    }
}
