using System;
using System.Collections.Generic;
using InAsync.Security.PasswordHashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PasswordHashing.Tests {

    [TestClass]
    public class ModularCryptFormatTests {

        [TestMethod]
        public void Ctor() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => new ModularCryptFormat(item.phfId, item.content), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.PhfId.Is(item.phfId, message);
                actual.Content.Is(item.content, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, string phfId, string content, Type expectedExceptionType)> TestCases() => new(int testNumber, string phfId, string content, Type expectedExceptionType)[]{
                ( 0, null , "content", typeof(ArgumentNullException)),
                ( 1, "phf", null     , typeof(ArgumentNullException)),
                (10, "phf", "content", null),
            };
        }

        [TestMethod]
        public new void ToString() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                if (!AssertException.TryExecute(() => item.mcf.ToString(), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.Is(item.expected, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, ModularCryptFormat mcf, string expected, Type expectedExceptionType)> TestCases() => new(int testNumber, ModularCryptFormat mcf, string expected, Type expectedExceptionType)[]{
                (10, new ModularCryptFormat("phf", "content"), "$phf$content", null),
            };
        }

        [TestMethod]
        public void TryParse() {
            foreach (var item in TestCases()) {
                var message = $"No.{item.testNumber}";
                ModularCryptFormat actualResult = null;
                if (!AssertException.TryExecute(() => ModularCryptFormat.TryParse(item.hashStr, out actualResult), item.expectedExceptionType, out var actual, message)) {
                    continue;
                }

                actual.Is(item.expected, message);
                actualResult.Is(item.expectedResult, message);
            }

            // テストケース定義。
            IEnumerable<(int testNumber, string hashStr, bool expected, ModularCryptFormat expectedResult, Type expectedExceptionType)> TestCases() => new(int testNumber, string hashStr, bool expected, ModularCryptFormat expectedResult, Type expectedExceptionType)[]{
                (10, null              , false, null                                        , null),
                (11, ""                , false, null                                        , null),
                (12, "phf"             , false, null                                        , null),
                (13, "phf$"            , false, null                                        , null),
                (14, "phf$content"     , false, null                                        , null),
                (15, "$"               , false, null                                        , null),
                (16, "$$"              , false, null                                        , null),
                (17, "$phf"            , false, null                                        , null),
                (18, "$phf$"           , false, null                                        , null),
                (19, "$phf$content"    , true , new ModularCryptFormat("phf", "content")    , null),
                (20, "$phf$content$"   , true , new ModularCryptFormat("phf", "content$")   , null),
                (21, "$phf$content$foo", true , new ModularCryptFormat("phf", "content$foo"), null),
            };
        }
    }
}