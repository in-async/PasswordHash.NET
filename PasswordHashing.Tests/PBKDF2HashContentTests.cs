using System;
using System.Collections.Generic;
using InAsync.Security.PasswordHashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHashing.Tests {

    [TestClass]
    public class PBKDF2HashContentTests {

        [TestMethod]
        public void Ctor() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => new PBKDF2HashContent(item.iterationCount, item.salt, item.derivedKey), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.IterationCount.Is(item.iterationCount, message);
                actual.Salt.Is(item.salt, message);
                actual.DerivedKey.Is(item.derivedKey, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, int iterationCount, byte[] salt, byte[] derivedKey, Type expectedExceptionType)> TestCases() => new(int testNumber, int iterationCount, byte[] salt, byte[] derivedKey, Type expectedExceptionType)[]{
                ( 0, 1, Array.Empty<byte>(), null               , typeof(ArgumentNullException)),
                ( 1, 1, null               , Array.Empty<byte>(), typeof(ArgumentNullException)),
                ( 2, 0, Array.Empty<byte>(), Array.Empty<byte>(), typeof(ArgumentOutOfRangeException)),
                (10, 1, Array.Empty<byte>(), Array.Empty<byte>(), null),
            };
        }

        [TestMethod]
        public new void ToString() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => item.content.ToString(), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.Is(item.expected, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, PBKDF2HashContent content, string expected, Type expectedExceptionType)> TestCases() => new(int testNumber, PBKDF2HashContent content, string expected, Type expectedExceptionType)[]{
                (10, new PBKDF2HashContent(1, Array.Empty<byte>(), Array.Empty<byte>()), "1$$"    , null),
                (11, new PBKDF2HashContent(2, new byte[]{ 0x01 } , new byte[]{ 0x02 } ), "2$AQ$Ag", null),
                (12, new PBKDF2HashContent(3, new byte[]{ 0xfb } , new byte[]{ 0xfc } ), "3$.w$/A", null),
            };
        }

        [TestMethod]
        public void TryParse() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                PBKDF2HashContent actualResult = null;
                if (!AssertException.TryExecute(() => PBKDF2HashContent.TryParse(item.content, out actualResult), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.Is(item.expected, message);
                actualResult.Is(item.expectedResult, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, string content, bool expected, PBKDF2HashContent expectedResult, Type expectedExceptionType)> TestCases() => new(int testNumber, string content, bool expected, PBKDF2HashContent expectedResult, Type expectedExceptionType)[]{
                (10, null     , false, null                                                              , null),
                (11, ""       , false, null                                                              , null),
                (12, "1"      , false, null                                                              , null),
                (13, "1$"     , false, null                                                              , null),
                (14, "1$$"    , true , new PBKDF2HashContent(1, Array.Empty<byte>(), Array.Empty<byte>()), null),
                (15, "a$$"    , false, null                                                              , null),
                (16, "1$$$"   , false, null                                                              , null),
                (17, "0$$"    , false, null                                                              , null),
                (18, "1$a$"   , false, null                                                              , null),
                (19, "1$$a"   , false, null                                                              , null),
                (20, "2$AQ$"  , true , new PBKDF2HashContent(2, new byte[]{ 0x01 } , Array.Empty<byte>()), null),
                (21, "2$$Ag"  , true , new PBKDF2HashContent(2, Array.Empty<byte>(), new byte[]{ 0x02 } ), null),
                (22, "2$AQ$Ag", true , new PBKDF2HashContent(2, new byte[]{ 0x01 } , new byte[]{ 0x02 } ), null),
                (23, "3$.w$/A", true , new PBKDF2HashContent(3, new byte[]{ 0xfb } , new byte[]{ 0xfc } ), null),
            };
        }
    }
}