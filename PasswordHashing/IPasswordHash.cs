namespace Inasync.Security.PasswordHashing {

    /// <summary>
    /// パスワードハッシュのモデル。
    /// </summary>
    public interface IPasswordHash {

        ///// <summary>
        ///// ハッシュ値。
        ///// </summary>
        //byte[] Hash { get; }

        /// <summary>
        /// パスワードハッシュと <paramref name="password"/> が同じパスワードを表すかどうかを返します。
        /// </summary>
        /// <param name="password">検査対象のパスワード。</param>
        /// <returns>パスワードハッシュと <paramref name="password"/> が同じパスワードを表していれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        bool Verify(string password);
    }
}