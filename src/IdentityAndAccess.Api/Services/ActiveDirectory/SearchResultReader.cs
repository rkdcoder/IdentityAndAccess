using System.DirectoryServices;

namespace IdentityAndAccess.Api.Services.ActiveDirectory
{
    /// <summary>
    /// Leitura tolerante dos atributos já trazidos por uma busca (<see cref="SearchResult"/>), sem nova ida ao servidor.
    /// Só existem os atributos pedidos em <see cref="DirectorySearcher.PropertiesToLoad"/> e que têm valor.
    /// </summary>
    internal static class SearchResultReader
    {
        public static string? GetString(SearchResult result, string name)
            => Read(result, name, AdAttributeConverter.ToStringValue, null);

        public static int GetInt(SearchResult result, string name)
            => Read(result, name, AdAttributeConverter.ToInt, 0);

        public static DateTime? GetDate(SearchResult result, string name)
            => Read(result, name, AdAttributeConverter.ToDate, null);

        public static DateTime? GetFileTime(SearchResult result, string name)
            => Read(result, name, AdAttributeConverter.ToFileTime, null);

        public static List<string> GetMulti(SearchResult result, string name)
        {
            var list = new List<string>();

            try
            {
                var values = result.Properties[name];
                foreach (var item in values)
                    if (item is not null)
                        list.Add(item.ToString()!);
            }
            catch { }

            return list;
        }

        private static T Read<T>(SearchResult result, string name, Func<object?, T> convert, T fallback)
        {
            try
            {
                var values = result.Properties[name];
                return values.Count == 0 ? fallback : convert(values[0]);
            }
            catch { return fallback; }
        }
    }
}
