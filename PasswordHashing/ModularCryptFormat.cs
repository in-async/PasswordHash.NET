using System;

namespace Inasync.Security.PasswordHashing {

    /// <summary>
    /// Modular Crypt Format ベースの抽象クラス。
    /// </summary>
    /// <typeparam name="TModularCryptFormatContent"></typeparam>
    public abstract class ModularCryptFormat<TModularCryptFormatContent> {

        /// <summary>
        /// <see cref="ModularCryptFormat{TModularCryptFormatContent}"/> のコンストラクタ。
        /// </summary>
        /// <param name="phfId">パスワードハッシュ関数の識別子。</param>
        /// <param name="content">パスワードハッシュ関数に依存した構成内容。</param>
        public ModularCryptFormat(string phfId, TModularCryptFormatContent content) {
            PhfId = phfId ?? throw new ArgumentNullException(nameof(phfId));
            Content = content;
        }

        /// <summary>
        /// パスワードハッシュ関数の識別子。
        /// </summary>
        public string PhfId { get; }

        /// <summary>
        /// パスワードハッシュ関数に依存した構成内容。
        /// </summary>
        public TModularCryptFormatContent Content { get; }

        /// <summary>
        /// パスワードハッシュ文字列を返します。
        /// </summary>
        /// <returns></returns>
        public override string ToString() {
            return $"${PhfId}${Content}";
        }
    }

    /// <summary>
    /// Modular Crypt Format のモデルクラス。
    /// </summary>
    public class ModularCryptFormat : ModularCryptFormat<string> {

        /// <summary>
        /// <see cref="ModularCryptFormat"/> のコンストラクタ。
        /// </summary>
        /// <param name="phfId">パスワードハッシュ関数の識別子。</param>
        /// <param name="content">パスワードハッシュ関数に依存した構成内容。</param>
        public ModularCryptFormat(string phfId, string content) : base(phfId, content) {
            if (content == null) throw new ArgumentNullException(nameof(content));
        }

        /// <summary>
        /// パスワードハッシュ文字列を解析します。
        /// </summary>
        /// <param name="hashStr">解析対象のパスワードハッシュ文字列。</param>
        /// <param name="result">解析結果の <see cref="ModularCryptFormat"/> インスタンス。</param>
        /// <returns>解析に成功すれば <c>true</c>、それ以外なら <c>false</c>。</returns>
        public static bool TryParse(string hashStr, out ModularCryptFormat result) {
            result = null;
            if (hashStr == null) return false;
            if (hashStr.StartsWith("$") == false) return false;

            var elems = hashStr.Split(new[] { '$' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (elems.Length != 2) return false;

            result = new ModularCryptFormat(elems[0], elems[1]);
            return true;
        }
    }
}