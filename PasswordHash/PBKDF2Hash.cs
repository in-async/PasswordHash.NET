using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

// $pbkdf2-sha128$10000$aahFBtwl6pgf9/7DzZMyjw$g55v6x91vB13jBQNs8N1i3WQbwA
// $pbkdf2-sha256$29000$9t7be09prfXee2/NOUeotQ$Y.RDnnq8vsezSZSKy1QNy6xhKPdoBIwc.0XDdRm9sJ8
namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// PBKDF2 によって算出されたパスワードハッシュのモデル。
    /// </summary>
    public class PBKDF2Hash : ModularCryptFormat<PBKDF2HashContent>, IPasswordHash {
        public const string HashIdPrefix = "pbkdf2";

        public PBKDF2Hash(HashAlgorithmName hashAlgorithm, PBKDF2HashContent content) : base(GetHashId(hashAlgorithm), content) {
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// 使用されたハッシュ関数。
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get; }

        /// <summary>
        /// パスワードハッシュと <paramref name="password"/> が同じ文字列かどうかを返します。
        /// </summary>
        /// <param name="password">検査対象のパスワード。</param>
        /// <returns>パスワードハッシュと <paramref name="password"/> が同じ文字列を表していれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public bool Verify(string password) {
            if (password == null) throw new ArgumentNullException(nameof(password));

#if NET472 || NETCOREAPP2_0
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt: Salt, iterations: IterationCount, hashAlgorithm: HashAlgorithm)) {
#else
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt: Content.Salt, iterations: Content.IterationCount)) {
#endif
                var dk = deriveBytes.GetBytes(Content.Hash.Length);
                return Content.Hash.SequenceEqual(dk);
            }
        }

        /// <summary>
        /// ハッシュ文字列を解析します。
        /// </summary>
        /// <param name="hashStr">解析対象のハッシュ文字列。</param>
        /// <param name="result">解析結果の <see cref="PBKDf2Hash"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool TryParse(string hashStr, out PBKDF2Hash result) {
            result = null;
            if (ModularCryptFormat.TryParse(hashStr, out var mcf) == false) return false;
            if (TryExtractHashAlgorithm(mcf.HashId, out var hashAlgorithm) == false) return false;
            if (PBKDF2HashContent.TryParse(mcf.Content, out var content) == false) return false;

            result = new PBKDF2Hash(hashAlgorithm, content);
            return true;
        }

        #region Helper

        /// <summary>
        /// ハッシュ関数に応じた識別子を返します。
        /// </summary>
        /// <param name="hashAlgorithm">対象のハッシュ関数。</param>
        /// <returns>ハッシュ関数に応じた識別子。<c>null</c> は返しません。</returns>
        private static string GetHashId(HashAlgorithmName hashAlgorithm) {
            if (hashAlgorithm == HashAlgorithmName.SHA1) {
                return HashIdPrefix;
            }
            else {
                return HashIdPrefix + '-' + hashAlgorithm.Name.ToLowerInvariant();
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="hashId"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        private static bool TryExtractHashAlgorithm(string hashId, out HashAlgorithmName result) {
            Debug.Assert(hashId != null);

            string hashIdPrefix;
            string hashAlgorithmStr;
            var hashSplitIdx = hashId.IndexOf('-');
            if (hashSplitIdx < 0) {
                hashIdPrefix = hashId;
                hashAlgorithmStr = null;
            }
            else {
                var hashIdElems = hashId.Split(new[] { '-' }, 2);
                hashIdPrefix = hashIdElems[0];
                hashAlgorithmStr = hashIdElems[1];
            }

            if (hashIdPrefix != HashIdPrefix) return false;

            switch (hashAlgorithmStr) {
                case null:
                    result = HashAlgorithmName.SHA1;
                    break;

                case "sha256":
                    result = HashAlgorithmName.SHA256;
                    break;

                case "sha384":
                    result = HashAlgorithmName.SHA384;
                    break;

                case "sha512":
                    result = HashAlgorithmName.SHA512;
                    break;

                default:
                    return false;
            }
            return true;
        }

        #endregion Helper
    }
}