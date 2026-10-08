using System.DirectoryServices;

namespace IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory.Internal
{
    /// <summary>
    /// Leitura tolerante de atributos de <see cref="DirectoryEntry"/>: atributo ausente ou ilegível vira valor vazio.
    /// </summary>
    internal static class DirectoryEntryReader
    {
        public static string? GetString(DirectoryEntry? entry, string name)
            => Read(entry, name, AdAttributeConverter.ToStringValue, null);

        public static int GetInt(DirectoryEntry? entry, string name)
            => Read(entry, name, AdAttributeConverter.ToInt, 0);

        public static DateTime? GetDate(DirectoryEntry? entry, string name)
            => Read(entry, name, AdAttributeConverter.ToDate, null);

        public static DateTime? GetFileTime(DirectoryEntry? entry, string name)
            => Read(entry, name, AdAttributeConverter.ToFileTime, null);

        public static IReadOnlyList<string> GetMulti(DirectoryEntry? entry, string name)
        {
            try
            {
                var values = entry?.Properties[name];
                if (values is null || values.Count == 0)
                    return Array.Empty<string>();

                var list = new List<string>(values.Count);
                foreach (var item in values)
                    if (item is not null)
                        list.Add(item.ToString()!);

                return list;
            }
            catch { return Array.Empty<string>(); }
        }

        private static T Read<T>(DirectoryEntry? entry, string name, Func<object?, T> convert, T fallback)
        {
            try { return convert(entry?.Properties[name]?.Value); }
            catch { return fallback; }
        }
    }
}
