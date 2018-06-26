using System;

namespace InAsync.Security.PasswordHash {

    /// <summary>
    /// Modular Crypt Format
    /// </summary>
    public abstract class ModularCryptFormat<TModularCryptFormatContent> {

        public ModularCryptFormat(string hashId, TModularCryptFormatContent content) {
            HashId = hashId;
            Content = content;
        }

        /// <summary>
        /// ハッシュ識別子。
        /// </summary>
        public string HashId { get; }

        /// <summary>
        ///
        /// </summary>
        public TModularCryptFormatContent Content { get; }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public override string ToString() {
            return $"${HashId}${Content}";
        }
    }

    /// <summary>
    /// Modular Crypt Format
    /// </summary>
    public class ModularCryptFormat : ModularCryptFormat<string> {

        public ModularCryptFormat(string hashId, string content) : base(hashId, content) {
        }

        /// <summary>
        /// ハッシュ文字列を解析します。
        /// </summary>
        /// <param name="hashStr">解析対象のハッシュ文字列。</param>
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