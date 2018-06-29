using System;
using System.Collections.Generic;

namespace InAsync.Security.PasswordHashing {

    /// <summary>
    /// パスワードハッシュを包括的に扱うファサードクラス。
    /// </summary>
    public static class PasswordHash {

        /// <summary>
        /// パスワードハッシュ文字列を解析して <see cref="IPasswordHash"/> インスタンスを返すパーサーデリゲート。
        /// </summary>
        /// <param name="hashStr">解析対象のパスワードハッシュ文字列。</param>
        /// <param name="result">解析結果の <see cref="IPasswordHash"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public delegate bool TryParseDelegate(string hashStr, out IPasswordHash result);

        /// <summary>
        /// パスワードハッシュ文字列を解析して <see cref="IPasswordHash"/> インスタンスを返すパーサープロダイバー。
        /// <para>キー : Modular Crypt Format に定義されている、パスワードハッシュ関数の識別子。</para>
        /// <para>値 : キーに対応するパスワードハッシュ文字列を解析するパーサーデリゲート。</para>
        /// </summary>
        public static readonly IDictionary<string, TryParseDelegate> TryParseProvider = new Dictionary<string, TryParseDelegate> {
            [PBKDF2Hash.PhfIdPrefix] = (string hashStr, out IPasswordHash result) => {
                if (PBKDF2Hash.TryParse(hashStr, out var tmp)) {
                    result = tmp;
                    return true;
                }
                else {
                    result = null;
                    return false;
                }
            },
        };

        /// <summary>
        /// パスワードハッシュ文字列を解析します。
        /// </summary>
        /// <param name="hashStr">解析対象のパスワードハッシュ文字列。</param>
        /// <param name="result">解析結果の <see cref="IPasswordHash"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool TryParse(string hashStr, out IPasswordHash result) {
            result = null;
            if (ModularCryptFormat.TryParse(hashStr, out var mcf) == false) return false;

            if (TryParseProvider.TryGetValue(mcf.PhfId, out var tryParse) == false) return false;
            return tryParse(hashStr, out result);
        }

        /// <summary>
        /// パスワードハッシュ文字列と <paramref name="password"/> が同じパスワードを表すかどうかを返します。
        /// </summary>
        /// <param name="password">検査対象のパスワード。</param>
        /// <param name="hashStr">比較対象となるパスワードハッシュ文字列。</param>
        /// <returns>パスワードハッシュと <paramref name="password"/> が同じパスワードを表していれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> 又は <paramref name="hashStr"/> が <c>null</c>。</exception>
        /// <exception cref="FormatException"><paramref name="hashStr"/> がパスワードハッシュの文字列形式ではない。</exception>
        public static bool Verify(string password, string hashStr) {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (hashStr == null) throw new ArgumentNullException(nameof(hashStr));

            if (TryParse(hashStr, out var hash) == false) throw new FormatException(nameof(hashStr));
            return hash.Verify(password);
        }
    }
}