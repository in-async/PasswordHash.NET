using System;

namespace Microsoft.VisualStudio.TestTools.UnitTesting {

    public static class AssertException {

        /// <summary>
        /// テスト対象コードを実行し、例外が無ければその戻り値を <paramref name="actual"/> に代入して <c>true</c> を返します。
        /// 例外が生じた場合には、例外の型が <paramref name="expectedExceptionType"/> と一致すれば <c>false</c> を返し、
        /// それ以外の場合には <see cref="AssertFailedException"/> をスローします。
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="testFunc">テスト対象コード</param>
        /// <param name="expectedExceptionType">期待される例外の型</param>
        /// <param name="actual">テスト対象コードの戻り値。テストの評価を行う為のオブジェクト</param>
        /// <param name="message"></param>
        /// <returns>テスト対象コードが例外なく実行された場合は <c>true</c>、期待される例外が生じた場合は <c>false</c>、それ以外は <see cref="AssertFailedException"/> がスローされます</returns>
        /// <exception cref="AssertFailedException"><paramref name="expectedExceptionType"/> が満たされなかった場合にスローされます</exception>
        public static bool TryExecute<T>(Func<T> testFunc, Type expectedExceptionType, out T actual, object message = null) {
            if (testFunc == null) { throw new ArgumentNullException(nameof(testFunc)); }

            try {
                // テスト対象コードを実行
                actual = testFunc();
            }
            catch (Exception ex)/* when (!(ex is AssertFailedException))*/ {
                // テストで期待される例外ではないので、再スロー
                //ex.GetType().Is(expectedExceptionType, ex.ToString());
                if (ex.GetType() != expectedExceptionType) { throw; }

                actual = default(T);
                return false;
            }

            // テスト対象コードが例外を生じなかったので、期待される例外は null のはず
            ObjectExtensions.Is(null, expectedExceptionType, message: message?.ToString());

            return true;
        }

        /// <summary>
        /// テスト対象コードを実行します。
        /// 例外が生じた場合には、例外の型が <paramref name="expectedExceptionType"/> と一致すれば <c>false</c> を返し、
        /// それ以外の場合には <see cref="AssertFailedException"/> をスローします。
        /// </summary>
        /// <param name="testAction">テスト対象コード</param>
        /// <param name="expectedExceptionType">期待される例外の型</param>
        /// <param name="message"></param>
        /// <returns>テスト対象コードが例外なく実行された場合は <c>true</c>、期待される例外が生じた場合は <c>false</c>、それ以外は <see cref="AssertFailedException"/> がスローされます</returns>
        /// <exception cref="AssertFailedException"><paramref name="expectedExceptionType"/> が満たされなかった場合にスローされます</exception>
        public static bool TryExecute(Action testAction, Type expectedExceptionType, object message = null) {
            if (testAction == null) { throw new ArgumentNullException(nameof(testAction)); }

            try {
                // テスト対象コードを実行
                testAction();
            }
            catch (Exception ex)/* when (!(ex is AssertFailedException))*/ {
                // テストで期待される例外ではないので、再スロー
                //ex.GetType().Is(expectedExceptionType, ex.ToString());
                if (ex.GetType() != expectedExceptionType) { throw; }

                return false;
            }

            // テスト対象コードが例外を生じなかったので、期待される例外は null のはず
            ObjectExtensions.Is(null, expectedExceptionType, message: message?.ToString());

            return true;
        }
    }
}