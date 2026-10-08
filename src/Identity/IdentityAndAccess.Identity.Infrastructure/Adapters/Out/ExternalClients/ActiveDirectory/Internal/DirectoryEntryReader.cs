using System.DirectoryServices;
using System.Reflection;

namespace IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory.Internal
{
    /// <summary>
    /// Leitura tolerante de atributos de <see cref="DirectoryEntry"/>: atributo ausente ou ilegível vira valor vazio.
    /// </summary>
    internal static class DirectoryEntryReader
    {
        public static string? GetString(DirectoryEntry? entry, string name)
        {
            try { return entry?.Properties[name]?.Value?.ToString(); }
            catch { return null; }
        }

        public static int GetInt(DirectoryEntry? entry, string name)
        {
            try
            {
                var value = entry?.Properties[name]?.Value;
                if (value is int i) return i;
                return int.TryParse(value?.ToString(), out var parsed) ? parsed : 0;
            }
            catch { return 0; }
        }

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

        public static bool? HasUserAccountControlFlag(DirectoryEntry? entry, int flag)
        {
            try
            {
                var value = entry?.Properties["userAccountControl"]?.Value;
                if (value is int i) return (i & flag) == flag;
                return int.TryParse(value?.ToString(), out var parsed) ? (parsed & flag) == flag : null;
            }
            catch { return null; }
        }

        public static DateTime? GetDate(DirectoryEntry? entry, string name)
        {
            try
            {
                var value = entry?.Properties[name]?.Value;
                if (value is DateTime d) return DateTime.SpecifyKind(d, DateTimeKind.Utc);
                return DateTime.TryParse(value?.ToString(), out var parsed) ? parsed.ToUniversalTime() : null;
            }
            catch { return null; }
        }

        /// <summary>
        /// Lê um atributo FILETIME (inteiro de 64 bits). 0 e <see cref="long.MaxValue"/> significam "nunca/não definido".
        /// </summary>
        public static DateTime? GetFileTime(DirectoryEntry? entry, string name)
        {
            try
            {
                var value = entry?.Properties[name]?.Value;
                if (value is null) return null;
                if (value is DateTime dt) return dt;

                var ticks = ToInt64(value);
                if (ticks is null || ticks == 0 || ticks == long.MaxValue) return null;

                return DateTime.FromFileTimeUtc(ticks.Value);
            }
            catch { return null; }
        }

        /// <summary>
        /// Converte o valor de um atributo "Large Integer" (long ou IADsLargeInteger COM) em <see cref="long"/>.
        /// </summary>
        public static long? ToInt64(object? value)
        {
            if (value is null) return null;
            if (value is long l) return l;

            var type = value.GetType();
            if (type.Name != "__ComObject") return null;

            var high = (int)type.InvokeMember("HighPart", BindingFlags.GetProperty, null, value, null)!;
            var low = (int)type.InvokeMember("LowPart", BindingFlags.GetProperty, null, value, null)!;

            return ((long)high << 32) + (uint)low;
        }
    }
}
