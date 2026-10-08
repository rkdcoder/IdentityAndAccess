using System.Reflection;

namespace IdentityAndAccess.Api.Services.ActiveDirectory
{
    /// <summary>
    /// Converte o valor bruto de um atributo do AD (DirectoryEntry ou SearchResult) para tipos .NET.
    /// </summary>
    internal static class AdAttributeConverter
    {
        public static string? ToStringValue(object? value) => value?.ToString();

        public static int ToInt(object? value)
        {
            if (value is int i) return i;
            return int.TryParse(value?.ToString(), out var parsed) ? parsed : 0;
        }

        public static DateTime? ToDate(object? value)
        {
            if (value is DateTime d) return DateTime.SpecifyKind(d, DateTimeKind.Utc);
            return DateTime.TryParse(value?.ToString(), out var parsed) ? parsed.ToUniversalTime() : null;
        }

        /// <summary>
        /// Atributo FILETIME (inteiro de 64 bits). 0 e <see cref="long.MaxValue"/> significam "nunca/não definido".
        /// </summary>
        public static DateTime? ToFileTime(object? value)
        {
            if (value is null) return null;
            if (value is DateTime dt) return dt;

            var ticks = ToInt64(value);
            if (ticks is null || ticks == 0 || ticks == long.MaxValue) return null;

            return DateTime.FromFileTimeUtc(ticks.Value);
        }

        /// <summary>
        /// Valor "Large Integer": <see cref="long"/> (SearchResult) ou IADsLargeInteger COM (DirectoryEntry).
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
