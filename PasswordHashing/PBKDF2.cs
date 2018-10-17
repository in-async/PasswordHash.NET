using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Inasync.Security.PasswordHashing {

    /// <summary>
    /// PBKDF2 によってパスワードハッシュを計算するクラス。
    /// </summary>
    public sealed class PBKDF2 {

        /// <summary>
        /// <see cref="PBKDF2"/> のコンストラクタ。
        /// </summary>
        public PBKDF2() : this(saltSize: 16) {
        }

        /// <summary>
        /// <see cref="PBKDF2"/> のコンストラクタ。
        /// </summary>
        /// <param name="saltSize">ソルトのバイトサイズ。</param>
        public PBKDF2(int saltSize) : this(saltSize, iterationCount: 10000) {
        }

        /// <summary>
        /// <see cref="PBKDF2"/> のコンストラクタ。
        /// </summary>
        /// <param name="saltSize">ソルトのバイトサイズ。</param>
        /// <param name="iterationCount">反復回数。</param>
        public PBKDF2(int saltSize, int iterationCount) : this(saltSize, iterationCount, HashAlgorithmName.SHA1) {
        }

#if NET472 || NETCOREAPP2_0
        public PBKDF2(int saltSize, int iterationCount, HashAlgorithmName hmacHashAlgorithm) {
#else

        /// <summary>
        /// <see cref="PBKDF2"/> のコンストラクタ。
        /// </summary>
        /// <param name="saltSize">ソルトのバイトサイズ。</param>
        /// <param name="iterationCount">反復回数。</param>
        /// <param name="hmacHashAlgorithm">HMAC で使用されるハッシュアルゴリズム。</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="saltSize"/> が 8 未満。又は <paramref name="iterationCount"/> が 0 以下。</exception>
        private PBKDF2(int saltSize, int iterationCount, HashAlgorithmName hmacHashAlgorithm) {
            Debug.Assert(hmacHashAlgorithm == HashAlgorithmName.SHA1);
#endif
            if (saltSize < 8) throw new ArgumentOutOfRangeException(nameof(saltSize), saltSize, null);
            if (iterationCount <= 0) throw new ArgumentOutOfRangeException(nameof(iterationCount), iterationCount, null);

            SaltSize = saltSize;
            IterationCount = iterationCount;
            HMACHashAlgorithm = hmacHashAlgorithm;
            DerivedKeyLength = GetPRFOutputLength(hmacHashAlgorithm);
        }

        /// <summary>
        /// ソルトのバイトサイズ。
        /// </summary>
        public int SaltSize { get; }

        /// <summary>
        /// 反復回数。
        /// </summary>
        public int IterationCount { get; }

        /// <summary>
        /// HMAC で使用されるハッシュアルゴリズム。
        /// </summary>
        public HashAlgorithmName HMACHashAlgorithm { get; }

        /// <summary>
        /// 導出された鍵のバイトサイズ。
        /// </summary>
        public int DerivedKeyLength { get; set; }

        /// <summary>
        /// <paramref name="password"/> のパスワードハッシュを返します。
        /// </summary>
        /// <param name="password">ハッシュ対象のパスワード。</param>
        /// <returns><see cref="PBKDF2Hash"/> のインスタンス。<c>null</c> は返さない。</returns>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> が <c>null</c>。</exception>
        public PBKDF2Hash Hash(string password) {
            if (password == null) throw new ArgumentNullException(nameof(password));

#if NET472 || NETCOREAPP2_0
            using (var deriveBytes = new Rfc2898DeriveBytes(password, saltSize: SaltSize, iterations: IterationCount, hashAlgorithm: HMACHashAlgorithm)) {
#else
            Debug.Assert(HMACHashAlgorithm == HashAlgorithmName.SHA1);
            using (var deriveBytes = new Rfc2898DeriveBytes(password, saltSize: SaltSize, iterations: IterationCount)) {
#endif
                var dk = deriveBytes.GetBytes(DerivedKeyLength);
                return new PBKDF2Hash(HMACHashAlgorithm, new PBKDF2HashContent(deriveBytes.IterationCount, deriveBytes.Salt, dk));
            }
        }

        #region Helper

        /// <summary>
        /// ハッシュアルゴリズムに応じた HMAC の出力バイトサイズを返します。
        /// </summary>
        /// <param name="hmacHashAlgorithm">対象のハッシュアルゴリズム。</param>
        /// <returns>ハッシュアルゴリズムに応じた HMAC の出力バイトサイズ。</returns>
        private static int GetPRFOutputLength(HashAlgorithmName hmacHashAlgorithm) {
            switch (hmacHashAlgorithm.Name) {
                // .NET Core の Rfc2898DeriveBytes が MD5 をサポートしていないのでコメントアウト。
                //case nameof(HashAlgorithmName.MD5):
                //    return 16;

                case nameof(HashAlgorithmName.SHA1):
                    return 20;

                case nameof(HashAlgorithmName.SHA256):
                    return 32;

                case nameof(HashAlgorithmName.SHA384):
                    return 48;

                case nameof(HashAlgorithmName.SHA512):
                    return 64;

                default:
                    throw new ArgumentOutOfRangeException(nameof(hmacHashAlgorithm), hmacHashAlgorithm, null);
            }
        }

        #endregion Helper
    }
}