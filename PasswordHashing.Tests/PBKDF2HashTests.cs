﻿using System;
using System.Security.Cryptography;
using Inasync;
using Inasync.Security.PasswordHashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHashing.Tests {

    [TestClass]
    public class PBKDF2HashTests {

        [TestMethod]
        public void Ctor() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => new PBKDF2Hash(item.hmacHashAlgorithm, item.content))
                    .Verify((actual, desc) => {
                        actual.HMACHashAlgorithm.Is(item.hmacHashAlgorithm, desc);
                        actual.Content.Is(item.content, desc);
                    }, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, HashAlgorithmName hmacHashAlgorithm, PBKDF2HashContent content, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, HashAlgorithmName.SHA1    , null                             , (Type)typeof(ArgumentNullException)),
                ( 1, default(HashAlgorithmName), Content_0(HashAlgorithmName.SHA1), (Type)typeof(ArgumentNullException)),
                ( 2, HashAlgorithmName.SHA256  , Content_0(HashAlgorithmName.SHA1), (Type)typeof(ArgumentException)),
                (10, HashAlgorithmName.SHA1    , Content_0(HashAlgorithmName.SHA1), (Type)null),
            };
        }

        [TestMethod]
        public void Verify() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => item.hash.Verify(item.password))
                    .Verify(item.expected, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, PBKDF2Hash hash, string password, bool expected, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_0, Array.Empty<byte>(), DerivedKey_0(HashAlgorithmName.SHA1)))  , Password_0, false, (Type)typeof(ArgumentException)),
                ( 1, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_0, Salt_0             , DerivedKey_0(HashAlgorithmName.SHA1)))  , null      , false, (Type)typeof(ArgumentNullException)),
                //( 2, new PBKDF2Hash(new HashAlgorithmName("foo"), new PBKDF2HashContent(IterationCount_0, Salt_0             , DerivedKey_0(HashAlgorithmName.SHA1)))  , Password_0, false, (Type)typeof(CryptographicException)),
                (10, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_0, Salt_0             , DerivedKey_0(HashAlgorithmName.SHA1)))  , Password_0, true , (Type)null),
                (11, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_0, Salt_0             , DerivedKey_0(HashAlgorithmName.SHA1)))  , Password_1, false, (Type)null),
                (12, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_0, Salt_0             , DerivedKey_0(HashAlgorithmName.SHA256))), Password_0, false, (Type)null),
                (13, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_0, Salt_0             , DerivedKey_1(HashAlgorithmName.SHA1)))  , Password_0, false, (Type)null),
                (14, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_0, Salt_1             , DerivedKey_0(HashAlgorithmName.SHA1)))  , Password_0, false, (Type)null),
                (15, new PBKDF2Hash(HashAlgorithmName.SHA1      , new PBKDF2HashContent(IterationCount_1, Salt_0             , DerivedKey_0(HashAlgorithmName.SHA1)))  , Password_0, false, (Type)null),
                //(16, new PBKDF2Hash(HashAlgorithmName.SHA256    , new PBKDF2HashContent(IterationCount_0, Salt_0             , DerivedKey_0(HashAlgorithmName.SHA1)))  , Password_0, false, (Type)null),
            };
        }

        [TestMethod]
        public void TryParse() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => (PBKDF2Hash.TryParse(item.hashStr, out var actualResult), actualResult).ToJson())
                    .Verify((item.expected, item.expectedResult).ToJson(), item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, string hashStr, bool expected, PBKDF2Hash expectedResult, Type expectedExceptionType)[] TestCases() => new[]{
                (10, "$pbkdf2$2$AAAAAAAAAAA$ev5EySepVq1cQ/aiG5axjtiH.s4"                                                                  , true , Hash_0(HashAlgorithmName.SHA1)  , (Type)null),
                (11, "pbkdf2$2$AAAAAAAAAAA$ev5EySepVq1cQ/aiG5axjtiH.s4"                                                                   , false, null                            , (Type)null),
                (12, "$bkdf2$2$AAAAAAAAAAA$ev5EySepVq1cQ/aiG5axjtiH.s4"                                                                   , false, null                            , (Type)null),
                (13, "$pbkdf2$2$AAAAAAAAAAAev5EySepVq1cQ/aiG5axjtiH.s4"                                                                   , false, null                            , (Type)null),
                (14, "$pbkdf2-$2$AAAAAAAAAAA$ev5EySepVq1cQ/aiG5axjtiH.s4"                                                                 , false, null                            , (Type)null),
                (15, "$pbkdf2-md5$2$AAAAAAAAAAA$ev5EySepVq1cQ/aiG5axjtiH.s4"                                                              , false, null                            , (Type)null),
                (16, "$pbkdf2-sha256$2$AAAAAAAAAAA$GsyZFvH1KkJzOCU3pHFuMArmlXdON1uJo8VheAB3BSo"                                           , false, null                            , (Type)null),
                (17, "$pbkdf2-sha384$2$AAAAAAAAAAA$RwuJsaZnOAXBmNaJMEwf/EpyhFOSjRSrYECYNlRiJXfun5tKrWEjY8Z/tBVw.U5u"                      , false, null                            , (Type)null),
                (18, "$pbkdf2-sha512$2$AAAAAAAAAAA$gARLBIWimddatzhOPHBsiwKx8gsv4vxc9AfyjTuOPsvcdiu9daIhrFm7tnn5ehMLAwiW.b/LjZbc6vVhV.4olQ", false, null                            , (Type)null),
            };
        }

        #region Helpers

        private static readonly string Password_0 = "foo";
        private static readonly byte[] Salt_0 = new byte[8];
        private static readonly int IterationCount_0 = 2;

        private static byte[] DerivedKey_0(HashAlgorithmName hmacHashAlgorithm) => new Rfc2898DeriveBytes(Password_0, Salt_0, IterationCount_0, hmacHashAlgorithm).GetBytes();

        private static PBKDF2HashContent Content_0(HashAlgorithmName hmacHashAlgorithm) => new PBKDF2HashContent(IterationCount_0, Salt_0, DerivedKey_0(hmacHashAlgorithm));

        private static PBKDF2Hash Hash_0(HashAlgorithmName hmacHashAlgorithm) => new PBKDF2Hash(hmacHashAlgorithm, Content_0(hmacHashAlgorithm));

        private static readonly string Password_1 = "bar";
        private static readonly byte[] Salt_1 = new byte[10];
        private static readonly int IterationCount_1 = 3;

        private static byte[] DerivedKey_1(HashAlgorithmName hmacHashAlgorithm) => new Rfc2898DeriveBytes(Password_1, Salt_1, IterationCount_1, hmacHashAlgorithm).GetBytes();

        #endregion Helpers
    }
}