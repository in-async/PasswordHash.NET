namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// パスワードハッシュを計算するインターフェース。
    /// </summary>
    /// <typeparam name="TPasswordHash"></typeparam>
    public interface IPasswordHasher<TPasswordHash> where TPasswordHash : IPasswordHash {

        /// <summary>
        /// <paramref name="password"/> のパスワードハッシュを返します。
        /// </summary>
        /// <param name="password">ハッシュ化する文字列。</param>
        /// <returns><typeparamref name="TPasswordHash"/> のインスタンス。<c>null</c> は返さない。</returns>
        TPasswordHash Hash(string password);
    }
}