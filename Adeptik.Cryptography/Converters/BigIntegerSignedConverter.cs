using Adeptik.Cryptography.Algorithms;
using Adeptik.Cryptography.Types;
using System;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Adeptik.Cryptography.Converters
{
    /// <summary>
    /// Converts <see cref="BigInteger"/> from <see cref="string"/>, containing digest of data.
    /// <para>
    /// The original input string is a <see cref="BigInteger"/>, call it original number.
    /// This value contains digest in least significant bits in the amount corresponding to the hash size of the hashing algorithm used.
    /// The remaining bits form the payload. The sign of the payload corresponds to the sign of the original number.
    /// </para>
    /// <para>
    /// When calculating the hash, сonversion of the payload into a byte array is performed for the its absolute value in little-endian order without trailing zeroes.
    /// </para>
    /// <para>
    /// When converting a hash to a number, its byte array is treated as a non-negative number in little-endian order.
    /// </para>
    /// </summary>
    public class BigIntegerSignedConverter : BigIntegerConverter
    {
        static BigIntegerSignedConverter()
        {
            CryptoConfig.AddAlgorithm(typeof(Adler32), "Adler-32");
        }

        private const string HashAlgorithmName = "Adler-32";

        /// <inheritdoc />
        /// <exception cref="InvalidOperationException">Hash algorithm is not applicable due to its hash size is 0.</exception>
        /// <exception cref="FormatException">Digest verification failed.</exception>
        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
            => ConvertFromSignedValue((BigInteger)base.ConvertFrom(context, culture, value));

        /// <summary>
        /// Creates hash algorithm implementation used for digest calculation.
        /// </summary>
        /// <param name="hashAlgorithmName">Hash algorithm name.</param>
        /// <returns>A <see cref="HashAlgorithm"/>.</returns>
        private static HashAlgorithm CreateHashAlgorithm(string hashAlgorithmName)
        {
            HashAlgorithm hashAlgorithm = HashAlgorithm.Create(hashAlgorithmName);
            if (hashAlgorithm.HashSize <= 0)
            {
                throw new InvalidOperationException($"Hash algorithm {hashAlgorithmName} with {hashAlgorithm.HashSize} hash size is not applicable.");
            }
            return hashAlgorithm;
        }

        /// <summary>
        /// Converts the given value of type <see cref="BigInteger"/>, containing digest, to the <see cref="BigIntegerSigned"/> type.
        /// </summary>
        /// <param name="value">A <see cref="BigInteger"/> value with digest.</param>
        /// <returns><see cref="BigIntegerSigned"/> value.</returns>
        /// <exception cref="InvalidOperationException">Hash algorithm is not applicable due to its hash size is 0.</exception>
        /// <exception cref="FormatException">Digest verification failed.</exception>
        protected static BigIntegerSigned ConvertFromSignedValue(BigInteger value)
        {
            var isNegative = value.Sign < 0;
            if (isNegative) value = BigInteger.Negate(value);
            using var hashAlgorithm = CreateHashAlgorithm(HashAlgorithmName);
            var digestDivider = BigInteger.Pow(0b10, hashAlgorithm.HashSize);
            var payloadAbsolute = value / digestDivider;
            var digest = value % digestDivider;

            var payloadBytes = payloadAbsolute.ToByteArray(isUnsigned: true, isBigEndian: false);
            var payloadHashBytes = hashAlgorithm.ComputeHash(payloadBytes);
            var payloadHash = new BigInteger(payloadHashBytes.AsSpan(), isUnsigned: true, isBigEndian: false);

            if (payloadHash != digest)
            {
                throw new FormatException("Value is not valid due to its digest verification failed.");
            }
            return new BigIntegerSigned(payloadAbsolute * (isNegative ? -1 : 1));
        }

        /// <summary>
        /// Converts signed value <see cref="BigIntegerSigned"/> to compound integer value.
        /// </summary>
        /// <param name="signedValue">Signed value.</param>
        /// <returns>Compound value.</returns>
        protected static BigInteger ConvertToBigInteger(BigIntegerSigned signedValue)
        {
            using var hashAlgorithm = CreateHashAlgorithm(HashAlgorithmName);
            var digestDivider = BigInteger.Pow(0b10, hashAlgorithm.HashSize);
            return signedValue.Payload * digestDivider + signedValue.GetDigest(HashAlgorithmName);
        }

        /// <summary>
        /// Converts <see cref="BigInteger"/> from <see cref="string"/>, containing digest of data, with hexadecimal output text format.
        /// </summary>
        /// <remarks>
        /// Converts a value to <see cref="string"/> in following format "[-]0x&lt;hex digits&gt;". For example, "-0x2a".
        /// </remarks>
        public new class HexOut : BigIntegerConverter.HexOut
        {
            /// <inheritdoc />
            /// <exception cref="InvalidOperationException">Hash algorithm is not applicable due to its hash size is 0.</exception>
            /// <exception cref="FormatException">Digest verification failed.</exception>
            public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
                => ConvertFromSignedValue((BigInteger)base.ConvertFrom(context, culture, value));

            /// <inheritdoc />
            public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
            {
                if (value?.GetType() != typeof(BigIntegerSigned) || destinationType != typeof(string))
                {
                    throw new InvalidOperationException($"Conversion from {value?.GetType()} to {destinationType} is not supported.");
                }
                var bigInt = ConvertToBigInteger((BigIntegerSigned)value);
                return base.ConvertTo(context, culture, bigInt, destinationType);
            }
        }

        /// <summary>
        /// Converts <see cref="BigInteger"/> from <see cref="string"/>, containing digest of data, with decimal output text format.
        /// </summary>
        /// <remarks>
        /// Converts a value to <see cref="string"/> in following format "[-]&lt;dec digits&gt;". For example, "-42".
        /// </remarks>
        public new class DecOut : BigIntegerConverter.DecOut
        {
            /// <inheritdoc />
            /// <exception cref="InvalidOperationException">Hash algorithm is not applicable due to its hash size is 0.</exception>
            /// <exception cref="FormatException">Digest verification failed.</exception>
            public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
                => ConvertFromSignedValue((BigInteger)base.ConvertFrom(context, culture, value));

            /// <inheritdoc />
            public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
            {
                if (value?.GetType() != typeof(BigIntegerSigned) || destinationType != typeof(string))
                {
                    throw new InvalidOperationException($"Conversion from {value?.GetType()} to {destinationType} is not supported.");
                }
                var bigInt = ConvertToBigInteger((BigIntegerSigned)value);
                return base.ConvertTo(context, culture, bigInt, destinationType);
            }
        }
    }
}
