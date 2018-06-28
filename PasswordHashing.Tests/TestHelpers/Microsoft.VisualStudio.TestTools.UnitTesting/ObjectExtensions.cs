using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace Microsoft.VisualStudio.TestTools.UnitTesting {

    public static class ObjectExtensions {

        public static void Is<T>(this T actual, T expected, object message = null) {
            if (typeof(T) != typeof(string) && typeof(IEnumerable).IsAssignableFrom(typeof(T))) {
                ((IEnumerable)actual).Cast<object>().Is(((IEnumerable)expected).Cast<object>(), message);
                return;
            }
            if (typeof(T).IsClass) {
                Assert.AreEqual(JsonConvert.SerializeObject(expected), JsonConvert.SerializeObject(actual), $"{new { expected, actual }}\n{message}");
            }
            else {
                Assert.AreEqual(expected, actual, $"{new { expected, actual }}\n{message}");
            }
        }

        public static void Is<T>(this IEnumerable<T> actual, IEnumerable<T> expected, object message = null) {
            CollectionAssert.AreEqual(expected.ToList(), actual.ToList(), $"{new { expected, actual }}\n{message}");
        }
    }
}