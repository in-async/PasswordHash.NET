using System;
using System.Security.Cryptography;

namespace PasswordHashing.Tests {

    public static class Rfc2898DeriveBytesExtensions {

        public static byte[] GetBytes(this Rfc2898DeriveBytes derivedBytes) {
            var dkLen = GetPRFOutputLength(derivedBytes.HashAlgorithm);
            return derivedBytes.GetBytes(dkLen);
        }

        private static int GetPRFOutputLength(HashAlgorithmName hashAlgorithm) {
            switch (hashAlgorithm.Name) {
                case nameof(HashAlgorithmName.SHA1):
                    return 20;

                case nameof(HashAlgorithmName.SHA256):
                    return 32;

                case nameof(HashAlgorithmName.SHA384):
                    return 48;

                case nameof(HashAlgorithmName.SHA512):
                    return 64;

                default:
                    throw new ArgumentException(hashAlgorithm.Name, nameof(hashAlgorithm));
            }
        }
    }
}