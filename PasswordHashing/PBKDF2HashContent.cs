using System;
using System.Diagnostics;
using System.Text;

namespace Inasync.Security.PasswordHashing {

    /// <summary>
    /// PBKDF2 固有の構成内容を表すモデルクラス。
    /// </summary>
    public class PBKDF2HashContent {

        /// <summary>
        /// <see cref="PBKDF2HashContent"/> のコンストラクタ。
        /// </summary>
        /// <param name="iterationCount">反復回数。1 以上の正の値。</param>
        /// <param name="salt">ソルト。</param>
        /// <param name="derivedKey">導出されたキー。</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterationCount"/> が 0 以下。</exception>
        internal PBKDF2HashContent(int iterationCount, byte[] salt, byte[] derivedKey) {
            if (iterationCount <= 0) throw new ArgumentOutOfRangeException(nameof(iterationCount), iterationCount, null);

            IterationCount = iterationCount;
            Salt = salt ?? throw new ArgumentNullException(nameof(salt));
            DerivedKey = derivedKey ?? throw new ArgumentNullException(nameof(derivedKey));
        }

        /// <summary>
        /// 反復回数。
        /// </summary>
        public int IterationCount { get; }

        /// <summary>
        /// ソルト。
        /// </summary>
        public byte[] Salt { get; }

        /// <summary>
        /// 導出されたキー。
        /// </summary>
        public byte[] DerivedKey { get; }

        /// <summary>
        /// 構成内容を MCF 形式の文字列で返します。
        /// </summary>
        /// <returns></returns>
        public override string ToString() {
            return $"{IterationCount}${AdaptedBase64Encode(Salt)}${AdaptedBase64Encode(DerivedKey)}";
        }

        /// <summary>
        /// PBKDF2 構成内容の MCF 文字列を解析します。
        /// </summary>
        /// <param name="content">PBKDF2 構成内容の MCF 文字列。</param>
        /// <param name="result">解析結果の <see cref="PBKDF2HashContent"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        internal static bool TryParse(string content, out PBKDF2HashContent result) {
            result = null;
            if (string.IsNullOrEmpty(content)) return false;
            var contentElems = content.Split('$');
            if (contentElems.Length != 3) return false;

            if (int.TryParse(contentElems[0], out var iterationCount) == false) return false;
            if (iterationCount <= 0) return false;

            byte[] salt, hash;
            try {
                salt = AdaptedBase64Decode(contentElems[1]);
                hash = AdaptedBase64Decode(contentElems[2]);
            }
            catch (FormatException) {
                return false;
            }

            result = new PBKDF2HashContent(iterationCount, salt, hash);
            return true;
        }

        #region Helpers

        /// <summary>
        /// バイナリを adapted base64 文字列にエンコードします。
        /// http://passlib.readthedocs.io/en/stable/lib/passlib.utils.binary.html#passlib.utils.binary.ab64_encode
        /// http://nullege.com/codes/search/passlib.utils.ab64_encode
        /// </summary>
        /// <param name="bin">変換対象のバイナリ。</param>
        /// <returns>adapted base64 でエンコードされた文字列。</returns>
        private static string AdaptedBase64Encode(byte[] bin) {
            return Convert.ToBase64String(bin).TrimEnd('=').Replace('+', '.');
        }

        /// <summary>
        /// adapted base64 文字列をデコードします。
        /// http://nullege.com/codes/search/passlib.utils.ab64_decode
        /// http://passlib.readthedocs.io/en/stable/lib/passlib.utils.binary.html#passlib.utils.binary.ab64_decode
        /// </summary>
        /// <param name="value">adapted base64 文字列。</param>
        /// <returns>デコードされたバイナリ。</returns>
        /// <exception cref="FormatException"><paramref name="value"/> が adapted base64 形式でない場合にスローされます。</exception>
        private static byte[] AdaptedBase64Decode(string value) {
            Debug.Assert(value != null);

            if (value == "") return Array.Empty<byte>();

            var paddingLen = (4 - value.Length % 4) & 0x3;
            var bldr = new StringBuilder(value);
            bldr.Replace('.', '+');
            bldr.Append('=', paddingLen);
            return Convert.FromBase64String(bldr.ToString());
        }

        #endregion Helpers
    }
}