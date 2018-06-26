using System;
using System.Collections.Generic;

namespace InAsync.Security.PasswordHash {

    public static class PasswordHash {

        private delegate bool TryParseDelegate(string hashStr, out IPasswordHash result);

        private static readonly IReadOnlyDictionary<string, TryParseDelegate> _tryParses = new Dictionary<string, TryParseDelegate> {
            [PBKDF2Hash.HashIdPrefix] = (string hashStr, out IPasswordHash result) => {
                if (PBKDF2Hash.TryParse(hashStr, out var tmp)) {
                    result = tmp;
                    return true;
                }
                else {
                    result = null;
                    return false;
                }
            },
        };

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hashStr"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static bool TryParse(string hashStr, out IPasswordHash result) {
            result = null;
            if (ModularCryptFormat.TryParse(hashStr, out var mcf) == false) return false;

            if (_tryParses.TryGetValue(mcf.HashId, out var tryParse) == false) return false;
            return tryParse(hashStr, out result);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="password"></param>
        /// <param name="hashStr"></param>
        /// <returns></returns>
        public static bool Verify(string password, string hashStr) {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (hashStr == null) throw new ArgumentNullException(nameof(hashStr));
            if (TryParse(hashStr, out var hash) == false) throw new FormatException(nameof(hashStr));
            return hash.Verify(password);
        }
    }
}