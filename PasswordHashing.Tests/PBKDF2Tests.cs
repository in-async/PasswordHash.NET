using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using InAsync.Security.PasswordHashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHashing.Tests {

    [TestClass]
    public class PBKDF2Tests {

        [TestMethod]
        public void Ctor() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => new PBKDF2(), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.HMACHashAlgorithm.Is(HashAlgorithmName.SHA1, message);
                actual.DerivedKeyLength.Is(20, message);
                actual.SaltSize.Is(16, message);
                actual.IterationCount.Is(10000, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, Type expectedExceptionType)> TestCases() => new(int testNumber, Type expectedExceptionType)[]{
                ( 0, null),
            };
        }

        [TestMethod]
        public void Ctor_saltSize() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => new PBKDF2(item.saltSize), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.HMACHashAlgorithm.Is(HashAlgorithmName.SHA1, message);
                actual.DerivedKeyLength.Is(20, message);
                actual.SaltSize.Is(item.saltSize, message);
                actual.IterationCount.Is(10000, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, int saltSize, Type expectedExceptionType)> TestCases() => new(int testNumber, int saltSize, Type expectedExceptionType)[]{
                ( 0, -1, typeof(ArgumentOutOfRangeException)),
                ( 1,  0, typeof(ArgumentOutOfRangeException)),
                ( 2,  7, typeof(ArgumentOutOfRangeException)),
                ( 3,  8, null),
            };
        }

        [TestMethod]
        public void Ctor_saltSize_iterationCount() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => new PBKDF2(item.saltSize, item.iterationCount), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.HMACHashAlgorithm.Is(HashAlgorithmName.SHA1, message);
                actual.DerivedKeyLength.Is(20, message);
                actual.SaltSize.Is(item.saltSize, message);
                actual.IterationCount.Is(item.iterationCount, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, int saltSize, int iterationCount, Type expectedExceptionType)> TestCases() => new(int testNumber, int saltSize, int iterationCount, Type expectedExceptionType)[]{
                ( 0, 10, -1, typeof(ArgumentOutOfRangeException)),
                ( 1, 10,  0, typeof(ArgumentOutOfRangeException)),
                ( 2, -1, 20, typeof(ArgumentOutOfRangeException)),
                ( 3,  0, 20, typeof(ArgumentOutOfRangeException)),
                ( 4,  7, 20, typeof(ArgumentOutOfRangeException)),
                ( 5,  8, 20, null),
            };
        }

        [TestMethod]
        public void Hash() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => item.hasher.Hash(item.password), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                byte[] expectedDerivedKey;
                using (var derivedBytes = new Rfc2898DeriveBytes(item.password, actual.Content.Salt, item.hasher.IterationCount, item.hasher.HMACHashAlgorithm)) {
                    expectedDerivedKey = derivedBytes.GetBytes(item.hasher.DerivedKeyLength);
                }

                actual.PhfId.Is(item.expectedPhfId, message);
                actual.HMACHashAlgorithm.Is(item.hasher.HMACHashAlgorithm, message);
                actual.Content.IterationCount.Is(item.hasher.IterationCount, message);
                actual.Content.Salt.Length.Is(item.hasher.SaltSize, message);
                actual.Content.DerivedKey.Length.Is(item.hasher.DerivedKeyLength, message);
                actual.Content.DerivedKey.Is(expectedDerivedKey, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, PBKDF2 hasher, string password, string expectedPhfId, Type expectedExceptionType)> TestCases() => new(int testNumber, PBKDF2 hasher, string password, string expectedPhfId, Type expectedExceptionType)[]{
                ( 0, new PBKDF2( 8,  2), null , null    , typeof(ArgumentNullException)),
                ( 1, new PBKDF2( 8,  2), "foo", "pbkdf2", null),
                ( 2, new PBKDF2( 8,  2), "bar", "pbkdf2", null),
                ( 3, new PBKDF2( 8, 12), "foo", "pbkdf2", null),
                ( 4, new PBKDF2(18,  2), "foo", "pbkdf2", null),
            };
        }
    }
}