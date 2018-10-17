using Newtonsoft.Json;

namespace PasswordHashing.Tests {

    public static class Extensions {

        /// <summary>
        /// オブジェクトをインデント付き JSON 文字列に変換します。
        /// </summary>
        /// <param name="obj">JSON 文字列に変換するオブジェクト。</param>
        /// <returns><paramref name="obj"/> の JSON 文字列表現。</returns>
        public static string ToJson(this object obj) => JsonConvert.SerializeObject(obj, Formatting.Indented);
    }
}