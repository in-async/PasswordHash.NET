using System;
using System.Text;

namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// PHC string format.
    /// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    /// </summary>
    public class PHCStringFormat {

        public PHCStringFormat(string id, string param, byte[] salt, byte[] hash) {
            Id = id;
            Param = param;
            Salt = salt;
            Hash = hash;
        }

        /// <summary>
        /// ハッシュ関数の識別子。
        /// </summary>
        public string Id { get; }

        /// <summary>
        /// パラメーター。
        /// </summary>
        public string Param { get; }

        /// <summary>
        /// ソルト。
        /// </summary>
        public byte[] Salt { get; }

        /// <summary>
        /// ハッシュ。
        /// </summary>
        public byte[] Hash { get; }

        /// <summary>
        /// PHC string format 形式の文字列を返します。
        /// </summary>
        /// <returns></returns>
        public override string ToString() {
            return $"${Id}${Param}${AdaptedBase64Encode(Salt)}${AdaptedBase64Encode(Hash)}";
        }

        /// <summary>
        /// ハッシュ文字列を解析します。
        /// </summary>
        /// <param name="hashStr">解析対象のハッシュ文字列。</param>
        /// <param name="result">解析結果の <see cref="PHCStringFormat"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool TryParse(string hashStr, out PHCStringFormat result) {
            result = null;
            if (hashStr == null) return false;
            if (hashStr.StartsWith("$") == false) return false;

            var elems = hashStr.Split(new[] { '$' }, StringSplitOptions.RemoveEmptyEntries);
            if (elems.Length != 4) return false;

            result = new PHCStringFormat(elems[0], elems[1], AdaptedBase64Decode(elems[2]), AdaptedBase64Decode(elems[3]));
            return true;
        }

        // http://nullege.com/codes/search/passlib.utils.ab64_encode
        private static string AdaptedBase64Encode(byte[] bin) {
            return Convert.ToBase64String(bin).TrimEnd('=').Replace('+', '.');
        }

        // http://nullege.com/codes/search/passlib.utils.ab64_decode
        public static byte[] AdaptedBase64Decode(string str) {
            var paddingLen = 4 - str.Length % 4;
            var bldr = new StringBuilder(str);
            bldr.Replace('.', '+');
            bldr.Append('=', paddingLen);
            return Convert.FromBase64String(bldr.ToString());
        }
    }
}