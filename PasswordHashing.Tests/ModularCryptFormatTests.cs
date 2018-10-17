using System;
using Inasync;
using Inasync.Security.PasswordHashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHashing.Tests {

    [TestClass]
    public class ModularCryptFormatTests {

        [TestMethod]
        public void Ctor() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => new ModularCryptFormat(item.phfId, item.content))
                    .Verify((actual, desc) => {
                        actual.PhfId.Is(item.phfId, desc);
                        actual.Content.Is(item.content, desc);
                    }, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, string phfId, string content, Type expectedExceptionType)[] TestCases() => new[]{
                ( 0, null , "content", (Type)typeof(ArgumentNullException)),
                ( 1, "phf", null     , (Type)typeof(ArgumentNullException)),
                (10, "phf", "content", (Type)null),
            };
        }

        [TestMethod]
        public new void ToString() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => item.mcf.ToString())
                    .Verify(item.expected, item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, ModularCryptFormat mcf, string expected, Type expectedExceptionType)[] TestCases() => new[]{
                (10, new ModularCryptFormat("phf", "content"), "$phf$content", (Type)null),
            };
        }

        [TestMethod]
        public void TryParse() {
            foreach (var item in TestCases()) {
                new TestCaseRunner($"No.{item.testNumber}")
                    .Run(() => (ModularCryptFormat.TryParse(item.hashStr, out var actualResult), actualResult).ToJson())
                    .Verify((item.expected, item.expectedResult).ToJson(), item.expectedExceptionType);
            }

            // テストケース定義。
            (int testNumber, string hashStr, bool expected, ModularCryptFormat expectedResult, Type expectedExceptionType)[] TestCases() => new[]{
                (10, null              , false, null                                        , (Type)null),
                (11, ""                , false, null                                        , (Type)null),
                (12, "phf"             , false, null                                        , (Type)null),
                (13, "phf$"            , false, null                                        , (Type)null),
                (14, "phf$content"     , false, null                                        , (Type)null),
                (15, "$"               , false, null                                        , (Type)null),
                (16, "$$"              , false, null                                        , (Type)null),
                (17, "$phf"            , false, null                                        , (Type)null),
                (18, "$phf$"           , false, null                                        , (Type)null),
                (19, "$phf$content"    , true , new ModularCryptFormat("phf", "content")    , (Type)null),
                (20, "$phf$content$"   , true , new ModularCryptFormat("phf", "content$")   , (Type)null),
                (21, "$phf$content$foo", true , new ModularCryptFormat("phf", "content$foo"), (Type)null),
            };
        }
    }
}