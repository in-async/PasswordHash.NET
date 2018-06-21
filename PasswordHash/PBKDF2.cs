using System;
using System.Linq;
using System.Security.Cryptography;

// OWASP Cheat Sheet https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
// Guideline https://www.sophos.com/ja-jp/press-office/press-releases/2013/11/ns-serious-security-how-to-store-your-users-passwords-safely.aspx
// MCF http://passlib.readthedocs.io/en/stable/modular_crypt_format.html
// see also http://www.nttdata.com/jp/ja/insights/blog/20170914.html
namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// PBKDF2 によってハッシュを生成、検証するクラス。
    /// </summary>
    public sealed class PBKDF2 {
        private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA1;

        public PBKDF2() : this(saltSize: 32) {
        }

        public PBKDF2(int saltSize) : this(saltSize, iterationCount: 10000) {
        }

        public PBKDF2(int saltSize, int iterationCount) : this(saltSize, iterationCount, DefaultHashAlgorithm) {
        }

#if NET472 || NETCOREAPP2_0
        public PBKDF2(int saltSize, int iterationCount, HashAlgorithmName hashAlgorithm) {
#else

        private PBKDF2(int saltSize, int iterationCount, HashAlgorithmName hashAlgorithm) {
#endif
            SaltSize = saltSize;
            IterationCount = iterationCount;
            HashAlgorithm = hashAlgorithm;
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
        /// パスワードのハッシュ文字列を計算します。
        /// </summary>
        /// <param name="password">ハッシュ化する文字列。</param>
        /// <returns><see cref="PBKDF2Hash"/> インスタンス。<c>null</c> は返さない。</returns>
        public PBKDF2Hash Hash(string password) {
#if NET472 || NETCOREAPP2_0
            using (var deriveBytes = new Rfc2898DeriveBytes(password, saltSize: SaltSize, iterations: IterationCount, hashAlgorithm: HashAlgorithm)) {
#else
            using (var deriveBytes = new Rfc2898DeriveBytes(password, saltSize: SaltSize, iterations: IterationCount)) {
#endif
                var dk = deriveBytes.GetBytes(DerivedKeyLength(HashAlgorithm));
                return new PBKDF2Hash(HashAlgorithm, deriveBytes.IterationCount, deriveBytes.Salt, dk);
            }
        }

        /// <summary>
        /// ハッシュ化されたパスワードが指定されたハッシュ文字列と一致するかどうかを返します。
        /// </summary>
        /// <param name="password">検査対象のパスワード。</param>
        /// <param name="hashStr">比較対象となるハッシュ文字列。</param>
        /// <returns>パスワードとハッシュ文字列が同じものを表していれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool Verify(string password, string hashStr) {
            if (PBKDF2Hash.TryParse(hashStr, out var pbkdf2Hash) == false) return false;
            return Verify(password, pbkdf2Hash);
        }

        /// <summary>
        /// ハッシュ化されたパスワードが指定されたハッシュ文字列と一致するかどうかを返します。
        /// </summary>
        /// <param name="password">検査対象のパスワード。</param>
        /// <param name="pbkdf2Hash">比較対象となるハッシュ文字列。</param>
        /// <returns>パスワードとハッシュ文字列が同じものを表していれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool Verify(string password, PBKDF2Hash pbkdf2Hash) {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (pbkdf2Hash == null) throw new ArgumentNullException(nameof(pbkdf2Hash));

#if NET472 || NETCOREAPP2_0
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt: pbkdf2Hash.Salt, iterations: pbkdf2Hash.IterationCount, hashAlgorithm: pbkdf2Hash.HashAlgorithm)) {
#else
            if (pbkdf2Hash.HashAlgorithm != DefaultHashAlgorithm) throw new ArgumentOutOfRangeException(nameof(pbkdf2Hash), pbkdf2Hash, "HashAlgorithm is not supported.");

            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt: pbkdf2Hash.Salt, iterations: pbkdf2Hash.IterationCount)) {
#endif
                var dk = deriveBytes.GetBytes(DerivedKeyLength(pbkdf2Hash.HashAlgorithm));
                return dk.SequenceEqual(pbkdf2Hash.Hash);
            }
        }

        #region Helper

        /// <summary>
        /// ハッシュ関数に応じた <c>dkLen</c> を返します。
        /// </summary>
        /// <param name="hashAlgorithm">対象のハッシュ関数。</param>
        /// <returns>ハッシュ関数に適した <c>dkLen</c>。</returns>
        private static int DerivedKeyLength(HashAlgorithmName hashAlgorithm) {
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