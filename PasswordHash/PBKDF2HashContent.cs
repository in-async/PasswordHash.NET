using System;
using System.Text;

namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// 
    /// </summary>
    public class PBKDF2HashContent {

        public PBKDF2HashContent(int iterationCount, byte[] salt, byte[] hash) {
            IterationCount = iterationCount;
            Salt = salt ?? throw new ArgumentNullException(nameof(salt));
            Hash = hash ?? throw new ArgumentNullException(nameof(hash));
        }

        /// <summary>
        /// ストレッチ回数。
        /// </summary>
        public int IterationCount { get; }

        /// <summary>
        /// ソルト。
        /// </summary>
        public byte[] Salt { get; }

        /// <summary>
        /// ハッシュ値。
        /// </summary>
        public byte[] Hash { get; }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public override string ToString() {
            return $"{IterationCount}${AdaptedBase64Encode(Salt)}${AdaptedBase64Encode(Hash)}";
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="content"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static bool TryParse(string content, out PBKDF2HashContent result) {
            if (content == null) throw new ArgumentNullException(nameof(content));

            result = null;
            var contentElems = content.Split('$');
            if (contentElems.Length != 3) return false;

            if (int.TryParse(contentElems[0], out var iterationCount) == false) return false;
            var salt = AdaptedBase64Decode(contentElems[1]);
            var hash = AdaptedBase64Decode(contentElems[2]);

            result = new PBKDF2HashContent(iterationCount, salt, hash);
            return true;
        }

        #region Helpers

        // http://nullege.com/codes/search/passlib.utils.ab64_encode
        private static string AdaptedBase64Encode(byte[] bin) {
            return Convert.ToBase64String(bin).TrimEnd('=').Replace('+', '.');
        }

        // http://nullege.com/codes/search/passlib.utils.ab64_decode
        public static byte[] AdaptedBase64Decode(string value) {
            var paddingLen = 4 - value.Length % 4;
            var bldr = new StringBuilder(value);
            bldr.Replace('.', '+');
            bldr.Append('=', paddingLen);
            return Convert.FromBase64String(bldr.ToString());
        }

        #endregion Helpers
    }
}