using System.Linq;
using System.Security.Cryptography;

// $pbkdf2-sha128$10000$aahFBtwl6pgf9/7DzZMyjw$g55v6x91vB13jBQNs8N1i3WQbwA
// $pbkdf2-sha256$29000$9t7be09prfXee2/NOUeotQ$Y.RDnnq8vsezSZSKy1QNy6xhKPdoBIwc.0XDdRm9sJ8
namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// PBKDF2 によって算出されたハッシュのモデルクラス。
    /// </summary>
    public class PBKDF2Hash : PHCStringFormat {
        private const string s_HashIdPrefix = "pbkdf2";

        public PBKDF2Hash(HashAlgorithmName hashAlgorithm, int iterationCount, byte[] salt, byte[] hash) : base(HashId(hashAlgorithm), iterationCount.ToString(), salt, hash) {
            IterationCount = iterationCount;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// ストレッチ回数。
        /// </summary>
        public int IterationCount { get; }

        /// <summary>
        /// 使用されたハッシュ関数。
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get; }

        /// <summary>
        /// ハッシュ文字列を解析します。
        /// </summary>
        /// <param name="hashStr">解析対象のハッシュ文字列。</param>
        /// <param name="result">解析結果の <see cref="PBKDf2Hash"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool TryParse(string hashStr, out PBKDF2Hash result) {
            result = null;
            if (PHCStringFormat.TryParse(hashStr, out var phcStr) == false) return false;

            var idElems = phcStr.Id.Split(new[] { '-' }, 2);
            if (idElems[0] != s_HashIdPrefix) return false;

            HashAlgorithmName hashAlgorithm;
            switch (idElems.ElementAtOrDefault(1)?.ToUpperInvariant()) {
                case nameof(HashAlgorithmName.MD5):
                    hashAlgorithm = HashAlgorithmName.MD5;
                    break;

                case null:
                    hashAlgorithm = HashAlgorithmName.SHA1;
                    break;

                case nameof(HashAlgorithmName.SHA256):
                    hashAlgorithm = HashAlgorithmName.SHA256;
                    break;

                case nameof(HashAlgorithmName.SHA384):
                    hashAlgorithm = HashAlgorithmName.SHA384;
                    break;

                case nameof(HashAlgorithmName.SHA512):
                    hashAlgorithm = HashAlgorithmName.SHA512;
                    break;

                default:
                    return false;
            }

            if (int.TryParse(phcStr.Param, out var iterationCount) == false) return false;

            result = new PBKDF2Hash(hashAlgorithm, iterationCount, phcStr.Salt, phcStr.Hash);
            return true;
        }

        #region Helper

        /// <summary>
        /// ハッシュ関数に応じた識別子を返します。
        /// </summary>
        /// <param name="hashAlgorithm">対象のハッシュ関数。</param>
        /// <returns>ハッシュ関数に応じた識別子。<c>null</c> は返しません。</returns>
        private static string HashId(HashAlgorithmName hashAlgorithm) {
            if (hashAlgorithm == HashAlgorithmName.SHA1) {
                return s_HashIdPrefix;
            }
            else {
                return s_HashIdPrefix + '-' + hashAlgorithm.Name.ToLowerInvariant();
            }
        }

        #endregion Helper
    }
}