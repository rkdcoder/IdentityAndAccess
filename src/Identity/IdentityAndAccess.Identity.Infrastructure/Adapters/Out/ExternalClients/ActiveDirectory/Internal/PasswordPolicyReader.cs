using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.DirectoryServices;

namespace IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory.Internal
{
    /// <summary>
    /// Lê (com cache) a idade máxima de senha (<c>maxPwdAge</c>) configurada no domínio.
    /// </summary>
    public sealed class PasswordPolicyReader
    {
        private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);

        private readonly ConcurrentDictionary<string, (DateTime Expire, Lazy<Task<TimeSpan>> Value)> _cache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ILogger<PasswordPolicyReader> _logger;

        public PasswordPolicyReader(ILogger<PasswordPolicyReader> logger) => _logger = logger;

        /// <summary>
        /// Idade máxima da senha. <see cref="TimeSpan.Zero"/> quando as senhas não expiram ou a política não pôde ser lida
        /// (falhas não ficam em cache).
        /// </summary>
        public async Task<TimeSpan> GetMaxPasswordAgeAsync(string domain, CancellationToken ct)
        {
            var now = DateTime.UtcNow;

            var cached = _cache.AddOrUpdate(
                domain,
                _ => (now.Add(CacheDuration), NewLoader(domain)),
                (_, current) => current.Expire > now ? current : (now.Add(CacheDuration), NewLoader(domain)));

            try
            {
                return await cached.Value.Value.WaitAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _cache.TryRemove(KeyValuePair.Create(domain, cached));
                _logger.LogWarning(ex, "Não foi possível ler a política de senha do domínio {Domain}.", domain);
                return TimeSpan.Zero;
            }
        }

        private static Lazy<Task<TimeSpan>> NewLoader(string domain)
            => new(() => Task.Run(() => Read(domain)));

        private static TimeSpan Read(string domain)
        {
            using var entry = new DirectoryEntry($"LDAP://{domain}");

            var ticks = DirectoryEntryReader.ToInt64(entry.Properties["maxPwdAge"]?.Value);

            if (ticks is null or 0 || ticks == long.MinValue)
                return TimeSpan.Zero;

            return TimeSpan.FromTicks(Math.Abs(ticks.Value));
        }
    }
}
