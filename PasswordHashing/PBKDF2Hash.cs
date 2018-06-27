using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace InAsync.Security.PasswordHashing {

    /// <summary>
    /// PBKDF2 によって算出されたパスワードハッシュのモデル。
    /// </summary>
    public class PBKDF2Hash : ModularCryptFormat<PBKDF2HashContent>, IPasswordHash {
        public const string PhfIdPrefix = "pbkdf2";

        /// <summary>
        /// <see cref="PBKDF2Hash"/> のコンストラクタ。
        /// </summary>
        /// <param name="hmacHashAlgorithm">HMAC に使用されたハッシュアルゴリズム。</param>
        /// <param name="content">PBKDF2 固有の構成内容。</param>
        public PBKDF2Hash(HashAlgorithmName hmacHashAlgorithm, PBKDF2HashContent content) : base(GetPhfId(hmacHashAlgorithm), content) {
            HMACHashAlgorithm = hmacHashAlgorithm;
        }

        /// <summary>
        /// HMAC に使用されたハッシュアルゴリズム。
        /// </summary>
        public HashAlgorithmName HMACHashAlgorithm { get; }

        /// <summary>
        /// パスワードハッシュと <paramref name="password"/> が同じパスワードを表すかどうかを返します。
        /// </summary>
        /// <param name="password">検査対象のパスワード。</param>
        /// <returns>パスワードハッシュと <paramref name="password"/> が同じパスワードを表していれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public bool Verify(string password) {
            if (password == null) throw new ArgumentNullException(nameof(password));

#if NET472 || NETCOREAPP2_0
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt: Salt, iterations: IterationCount, hmacHashAlgorithm: HMACHashAlgorithm)) {
#else
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt: Content.Salt, iterations: Content.IterationCount)) {
#endif
                var dk = deriveBytes.GetBytes(Content.DerivedKey.Length);
                return Content.DerivedKey.SequenceEqual(dk);
            }
        }

        /// <summary>
        /// パスワードハッシュ文字列を解析します。
        /// </summary>
        /// <param name="hashStr">解析対象のパスワードハッシュ文字列。</param>
        /// <param name="result">解析結果の <see cref="PBKDF2Hash"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool TryParse(string hashStr, out PBKDF2Hash result) {
            result = null;
            if (ModularCryptFormat.TryParse(hashStr, out var mcf) == false) return false;
            if (TryExtractHMACHashAlgorithm(mcf.PhfId, out var hmacHashAlgorithm) == false) return false;
            if (PBKDF2HashContent.TryParse(mcf.Content, out var content) == false) return false;

            result = new PBKDF2Hash(hmacHashAlgorithm, content);
            return true;
        }

        #region Helper

        /// <summary>
        /// PRF (HMAC-X) に応じたパスワードハッシュ関数の識別子を返します。
        /// </summary>
        /// <param name="hmacHashAlgorithm">HMAC に使用されたハッシュアルゴリズム。</param>
        /// <returns>PRF (HMAC-X) に応じたパスワードハッシュ関数の識別子。<c>null</c> は返しません。</returns>
        private static string GetPhfId(HashAlgorithmName hmacHashAlgorithm) {
            if (hmacHashAlgorithm == HashAlgorithmName.SHA1) {
                return PhfIdPrefix;
            }
            else {
                return PhfIdPrefix + '-' + hmacHashAlgorithm.Name.ToLowerInvariant();
            }
        }

        /// <summary>
        /// PBKDF2 のパスワードハッシュ関数識別子から使用されている HMAC ハッシュアルゴリズムを取得します。
        /// </summary>
        /// <param name="phfhId">パスワードハッシュ関数の識別子。</param>
        /// <param name="result">抽出された HMAC ハッシュアルゴリズム。</param>
        /// <returns>正常に HMAC ハッシュアルゴリズムを抽出できれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        private static bool TryExtractHMACHashAlgorithm(string phfhId, out HashAlgorithmName result) {
            Debug.Assert(phfhId != null);

            string hashIdPrefix;
            string hashAlgorithmStr;
            var hashSplitIdx = phfhId.IndexOf('-');
            if (hashSplitIdx < 0) {
                hashIdPrefix = phfhId;
                hashAlgorithmStr = null;
            }
            else {
                var hashIdElems = phfhId.Split(new[] { '-' }, 2);
                hashIdPrefix = hashIdElems[0];
                hashAlgorithmStr = hashIdElems[1];
            }

            if (hashIdPrefix != PhfIdPrefix) return false;

            switch (hashAlgorithmStr) {
                case "md5":
                    result = HashAlgorithmName.MD5;
                    break;

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