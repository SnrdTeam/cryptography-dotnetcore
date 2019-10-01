using System;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;

namespace Adeptik.Cryptography.Converters
{
    /// <summary>
    /// Converts <see cref="BigInteger"/> from <see cref="string"/>.
    /// </summary>
    /// <remarks>
    /// Integer value representing in one of the following formats:
    /// <list type="bullet">
    /// <item>Decimal</item>
    /// <item>Hexdecimal Starts with "0x"</item>
    /// </list>
    /// At the beginning of string could be a '-' sign (before '0x' in hex format), indicates that the value is negative. '+' sign is not supported, positive value should not have a sign.
    /// </remarks>
    public class BigIntegerConverter : TypeConverter
    {
        /// <inheritdoc />
        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
        {
            return sourceType == typeof(string);
        }

        /// <inheritdoc />
        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
        {
            ReadOnlySpan<char> spanValue = null;
            if (value is string stringValue)
            {
                spanValue = stringValue.AsSpan();
            }
            if (spanValue == null)
            {
                throw new InvalidOperationException($"Conversion from {value?.GetType()} to {typeof(BigInteger)} is not supported.");
            }
            if (spanValue.Length == 0)
            {
                throw new FormatException("Empty string is invalid integer value.");
            }
            var isNegative = spanValue.StartsWith("-".AsSpan());
            if (isNegative) spanValue = spanValue.Slice(1);
            if (spanValue.Length == 0)
            {
                throw new FormatException("Empty string is invalid integer value.");
            }

            // hex format
            if (spanValue.StartsWith("0x".AsSpan()))
            {
                spanValue = spanValue.Slice(2);
                if (spanValue.Length == 0)
                {
                    throw new FormatException("Empty hex string is invalid integer value.");
                }
                return BigInteger.Parse($"0{new string(spanValue)}", NumberStyles.AllowHexSpecifier) * (isNegative ? -1 : 1);
            }
            // dec format
            else
            {
                return BigInteger.Parse($"0{new string(spanValue)}", NumberStyles.None) * (isNegative ? -1 : 1);
            }
        }

        /// <inheritdoc />
        public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
        {
            return false;
        }

        /// <inheritdoc />
        public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Big integer converter with hexadecimal output text format. Converts a value to <see cref="string"/> in following format "[-]0x&lt;hex digits&gt;". For example, "-0x2a".
        /// </summary>
        public class HexOut : BigIntegerConverter
        {
            /// <inheritdoc />
            public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
            {
                return destinationType == typeof(string);
            }

            /// <inheritdoc />
            public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
            {
                if (value?.GetType() != typeof(BigInteger) || destinationType != typeof(string))
                {
                    throw new InvalidOperationException($"Conversion from {value?.GetType()} to {destinationType} is not supported.");
                }
                var bigIntValue = (BigInteger)value;

                var isNegative = bigIntValue.Sign < 0;
                if (isNegative) bigIntValue = BigInteger.Negate(bigIntValue);

                return @$"{(isNegative ? "-" : "")}0x{bigIntValue.ToString("x").TrimStart('0').PadLeft(1, '0')}";
            }
        }

        /// <summary>
        /// Big integer converter with decimal output text format. Converts a value to <see cref="string"/> in following format "[-]&lt;dec digits&gt;". For example, "-42".
        /// </summary>
        public class DecOut : BigIntegerConverter
        {
            /// <inheritdoc />
            public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
            {
                return destinationType == typeof(string);
            }

            /// <inheritdoc />
            public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
            {
                if (value?.GetType() != typeof(BigInteger) || destinationType != typeof(string))
                {
                    throw new InvalidOperationException($"Conversion from {value?.GetType()} to {destinationType} is not supported.");
                }
                var bigIntValue = (BigInteger)value;

                var isNegative = bigIntValue.Sign < 0;
                if (isNegative) bigIntValue = BigInteger.Negate(bigIntValue);

                return @$"{(isNegative ? "-" : "")}{bigIntValue.ToString().TrimStart('0').PadLeft(1, '0')}";
            }
        }
    }
}
