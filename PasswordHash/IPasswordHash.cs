namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// パスワードハッシュのモデル。
    /// </summary>
    public interface IPasswordHash {

        ///// <summary>
        ///// ハッシュ値。
        ///// </summary>
        //byte[] Hash { get; }

        /// <summary>
        /// パスワードハッシュと <paramref name="password"/> が同じ文字列かどうかを返します。
        /// </summary>
        /// <param name="password">検査対象のパスワード。</param>
        /// <returns>パスワードハッシュと <paramref name="password"/> が同じ文字列を表していれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        bool Verify(string password);
    }
}