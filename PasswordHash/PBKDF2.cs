using System;
using System.Security.Cryptography;

// OWASP Cheat Sheet https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
// Guideline https://www.sophos.com/ja-jp/press-office/press-releases/2013/11/ns-serious-security-how-to-store-your-users-passwords-safely.aspx
// MCF http://passlib.readthedocs.io/en/stable/modular_crypt_format.html
// see also http://www.nttdata.com/jp/ja/insights/blog/20170914.html
namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// PBKDF2 によってパスワードハッシュを計算するクラス。
    /// </summary>
    public sealed class PBKDF2 {

        public PBKDF2() : this(saltSize: 32) {
        }

        public PBKDF2(int saltSize) : this(saltSize, iterationCount: 10000) {
        }

        public PBKDF2(int saltSize, int iterationCount) : this(saltSize, iterationCount, HashAlgorithmName.SHA1) {
        }

#if NET472 || NETCOREAPP2_0
        public PBKDF2(int saltSize, int iterationCount, HashAlgorithmName hashAlgorithm) {
#else

        private PBKDF2(int saltSize, int iterationCount, HashAlgorithmName hashAlgorithm) {
#endif
            SaltSize = saltSize;
            IterationCount = iterationCount;
            HashAlgorithm = hashAlgorithm;
            DerivedKeyLength = GetDerivedKeyLength(hashAlgorithm);
        }

        /// <summary>
        /// ソルトのバイトサイズ。
        /// </summary>
        public int SaltSize { get; }

        /// <summary>
        /// ストレッチ回数。
        /// </summary>
        public int IterationCount { get; }

        /// <summary>
        /// 使用するハッシュ関数。
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get; }

        /// <summary>
        /// ハッシュのバイト長。
        /// </summary>
        public int DerivedKeyLength { get; }

        /// <summary>
        /// <paramref name="password"/> のパスワードハッシュを返します。
        /// </summary>
        /// <param name="password">ハッシュ化する文字列。</param>
        /// <returns><see cref="PBKDF2Hash"/> のインスタンス。<c>null</c> は返さない。</returns>
        public PBKDF2Hash Hash(string password) {
#if NET472 || NETCOREAPP2_0
            using (var deriveBytes = new Rfc2898DeriveBytes(password, saltSize: SaltSize, iterations: IterationCount, hashAlgorithm: HashAlgorithm)) {
#else
            using (var deriveBytes = new Rfc2898DeriveBytes(password, saltSize: SaltSize, iterations: IterationCount)) {
#endif
                var dk = deriveBytes.GetBytes(DerivedKeyLength);
                return new PBKDF2Hash(HashAlgorithm, new PBKDF2HashContent(deriveBytes.IterationCount, deriveBytes.Salt, dk));
            }
        }

        #region Helper

        /// <summary>
        /// ハッシュ関数に応じた <c>dkLen</c> を返します。
        /// </summary>
        /// <param name="hashAlgorithm">対象のハッシュ関数。</param>
        /// <returns>ハッシュ関数に適した <c>dkLen</c>。</returns>
        private static int GetDerivedKeyLength(HashAlgorithmName hashAlgorithm) {
            switch (hashAlgorithm.Name) {
                case nameof(HashAlgorithmName.MD5):
                    return 16;

                case null:
                    return 20;

                case nameof(HashAlgorithmName.SHA256):
                    return 32;

                case nameof(HashAlgorithmName.SHA384):
                    return 48;

                case nameof(HashAlgorithmName.SHA512):
                    return 64;

                default:
                    throw new ArgumentOutOfRangeException(nameof(hashAlgorithm), hashAlgorithm, null);
            }
        }

        #endregion Helper
    }
}