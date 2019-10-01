# Adeptik cryptography library

[![Nuget Package](https://flat.badgen.net/nuget/v/Adeptik.Cryptography)](https://www.nuget.org/packages/Adeptik.Cryptography/)

Adeptik cryptography  implementations for .NET Core.

Library includes:

Special type:

- BigIntegerSigned - big integer number with error control code included.

Type converters:

- BigIntegerConverter - big integer converter supports hex & decimal string representation for positive & negative numbers
- BigIntegerSignedConverter - convert and check bigintegersigned from hex & decimal representation (Adler-32 checksum used by default).

Algorithms:

- Adler32 - Adler-32 cyclic redundancy check algorithm as it described in [RFC1950](https://tools.ietf.org/html/rfc1950#section-9).

## Installation

Add reference for NuGet "Adeptik.CommandLineUtils" package in Visual Studio or run following in Package Manager Console:

    Install-Package Adeptik.Cryptography

Your project should target at list NETStandart 2.1.
