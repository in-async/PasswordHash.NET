using System;
using System.Security.Cryptography;
using Inasync;
using Inasync.Security.PasswordHashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHashing.Tests {

    [TestClass]
    public class PBKDF2Tests {

        [TestMethod]
        public void Ctor() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => new PBKDF2())
                    .Verify((actual, desc) => {
                        actual.HMACHashAlgorithm.Is(HashAlgorithmName.SHA1, desc);
                        actual.DerivedKeyLength.Is(20, desc);
                        actual.SaltSize.Is(16, desc);
                        actual.IterationCount.Is(10000, desc);
                    }, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, (Type)null),
            };
        }

        [TestMethod]
        public void Ctor_saltSize() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => new PBKDF2(item.saltSize))
                    .Verify((actual, desc) => {
                        actual.HMACHashAlgorithm.Is(HashAlgorithmName.SHA1, desc);
                        actual.DerivedKeyLength.Is(20, desc);
                        actual.SaltSize.Is(item.saltSize, desc);
                        actual.IterationCount.Is(10000, desc);
                    }, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, int saltSize, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, -1, (Type)typeof(ArgumentOutOfRangeException)),
                ( 1,  0, (Type)typeof(ArgumentOutOfRangeException)),
                ( 2,  7, (Type)typeof(ArgumentOutOfRangeException)),
                ( 3,  8, (Type)null),
            };
        }

        [TestMethod]
        public void Ctor_saltSize_iterationCount() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => new PBKDF2(item.saltSize, item.iterationCount))
                    .Verify((actual, desc) => {
                        actual.HMACHashAlgorithm.Is(HashAlgorithmName.SHA1, desc);
                        actual.DerivedKeyLength.Is(20, desc);
                        actual.SaltSize.Is(item.saltSize, desc);
                        actual.IterationCount.Is(item.iterationCount, desc);
                    }, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, int saltSize, int iterationCount, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, 10, -1, (Type)typeof(ArgumentOutOfRangeException)),
                ( 1, 10,  0, (Type)typeof(ArgumentOutOfRangeException)),
                ( 2, -1, 20, (Type)typeof(ArgumentOutOfRangeException)),
                ( 3,  0, 20, (Type)typeof(ArgumentOutOfRangeException)),
                ( 4,  7, 20, (Type)typeof(ArgumentOutOfRangeException)),
                ( 5,  8, 20, (Type)null),
            };
        }

        [TestMethod]
        public void Hash() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => item.hasher.Hash(item.password))
                    .Verify((actual, desc) => {
                        byte[] expectedDerivedKey;
                        using (var derivedBytes = new Rfc2898DeriveBytes(item.password, actual.Content.Salt, item.hasher.IterationCount, item.hasher.HMACHashAlgorithm)) {
                            expectedDerivedKey = derivedBytes.GetBytes(item.hasher.DerivedKeyLength);
                        }

                        actual.PhfId.Is(item.expectedPhfId, desc);
                        actual.HMACHashAlgorithm.Is(item.hasher.HMACHashAlgorithm, desc);
                        actual.Content.IterationCount.Is(item.hasher.IterationCount, desc);
                        actual.Content.Salt.Length.Is(item.hasher.SaltSize, desc);
                        actual.Content.DerivedKey.Length.Is(item.hasher.DerivedKeyLength, desc);
                        actual.Content.DerivedKey.Is(expectedDerivedKey, desc);
                    }, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, PBKDF2 hasher, string password, string expectedPhfId, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, new PBKDF2( 8,  2), null , null    , (Type)typeof(ArgumentNullException)),
                ( 1, new PBKDF2( 8,  2), "foo", "pbkdf2", (Type)null),
                ( 2, new PBKDF2( 8,  2), "bar", "pbkdf2", (Type)null),
                ( 3, new PBKDF2( 8, 12), "foo", "pbkdf2", (Type)null),
                ( 4, new PBKDF2(18,  2), "foo", "pbkdf2", (Type)null),
            };
        }
    }
}