using System;
using Inasync;
using InAsync.Security.PasswordHashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHashing.Tests {

    [TestClass]
    public class PBKDF2HashContentTests {

        [TestMethod]
        public void Ctor() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => new PBKDF2HashContent(item.iterationCount, item.salt, item.derivedKey))
                    .Verify((actual, desc) => {
                        actual.IterationCount.Is(item.iterationCount, desc);
                        actual.Salt.Is(item.salt, desc);
                        actual.DerivedKey.Is(item.derivedKey, desc);
                    }, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, int iterationCount, byte[] salt, byte[] derivedKey, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, 1, Array.Empty<byte>(), null               , (Type)typeof(ArgumentNullException)),
                ( 1, 1, null               , Array.Empty<byte>(), (Type)typeof(ArgumentNullException)),
                ( 2, 0, Array.Empty<byte>(), Array.Empty<byte>(), (Type)typeof(ArgumentOutOfRangeException)),
                (10, 1, Array.Empty<byte>(), Array.Empty<byte>(), (Type)null),
            };
        }

        [TestMethod]
        public new void ToString() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => item.content.ToString())
                    .Verify(item.expected, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, PBKDF2HashContent content, string expected, Type expectedExceptionType)[] TestCases() => new[]{
                (10, new PBKDF2HashContent(1, Array.Empty<byte>(), Array.Empty<byte>()), "1$$"    , (Type)null),
                (11, new PBKDF2HashContent(2, new byte[]{ 0x01 } , new byte[]{ 0x02 } ), "2$AQ$Ag", (Type)null),
                (12, new PBKDF2HashContent(3, new byte[]{ 0xfb } , new byte[]{ 0xfc } ), "3$.w$/A", (Type)null),
            };
        }

        [TestMethod]
        public void TryParse() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => (PBKDF2HashContent.TryParse(item.content, out var actualResult), actualResult).ToJson())
                    .Verify((item.expected, item.expectedResult).ToJson(), item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, string content, bool expected, PBKDF2HashContent expectedResult, Type expectedExceptionType)[] TestCases() => new[]{
                (10, null     , false, null                                                              , (Type)null),
                (11, ""       , false, null                                                              , (Type)null),
                (12, "1"      , false, null                                                              , (Type)null),
                (13, "1$"     , false, null                                                              , (Type)null),
                (14, "1$$"    , true , new PBKDF2HashContent(1, Array.Empty<byte>(), Array.Empty<byte>()), (Type)null),
                (15, "a$$"    , false, null                                                              , (Type)null),
                (16, "1$$$"   , false, null                                                              , (Type)null),
                (17, "0$$"    , false, null                                                              , (Type)null),
                (18, "1$a$"   , false, null                                                              , (Type)null),
                (19, "1$$a"   , false, null                                                              , (Type)null),
                (20, "2$AQ$"  , true , new PBKDF2HashContent(2, new byte[]{ 0x01 } , Array.Empty<byte>()), (Type)null),
                (21, "2$$Ag"  , true , new PBKDF2HashContent(2, Array.Empty<byte>(), new byte[]{ 0x02 } ), (Type)null),
                (22, "2$AQ$Ag", true , new PBKDF2HashContent(2, new byte[]{ 0x01 } , new byte[]{ 0x02 } ), (Type)null),
                (23, "3$.w$/A", true , new PBKDF2HashContent(3, new byte[]{ 0xfb } , new byte[]{ 0xfc } ), (Type)null),
            };
        }
    }
}