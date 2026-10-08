using Microsoft.Extensions.Options;
using Platform.Identity.Abstractions.Options;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory.Internal
{
    /// <summary>
    /// Descobre (via DNS) e valida (porta 389) os controladores de domínio de um domínio, com cache.
    /// </summary>
    public sealed class DomainControllerResolver
    {
        private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(1);

        private readonly ConcurrentDictionary<string, Lazy<Task<CacheEntry>>> _cache = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _probeLimiter = new(5);
        private readonly TimeSpan _discoveryTimeout;

        private sealed record CacheEntry(DateTime Expire, IReadOnlyList<string> DomainControllers);

        public DomainControllerResolver(IOptions<DirectoryServicesOptions> options)
        {
            _discoveryTimeout = TimeSpan.FromSeconds(Math.Max(1, options.Value.TimeoutSeconds));
        }

        /// <summary>
        /// Controladores de domínio em ordem aleatória (balanceamento simples).
        /// </summary>
        public async Task<IReadOnlyList<string>> ResolveAsync(string domain, CancellationToken ct)
        {
            if (IPAddress.TryParse(domain, out _))
                return new[] { domain };

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                // A descoberta é compartilhada entre requisições: não pode depender do token de quem a iniciou.
                var lazy = _cache.GetOrAdd(domain, d => new Lazy<Task<CacheEntry>>(() => DiscoverAsync(d)));

                CacheEntry entry;
                try
                {
                    entry = await lazy.Value.WaitAsync(ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    // Falhas não ficam em cache.
                    _cache.TryRemove(KeyValuePair.Create(domain, lazy));
                    throw;
                }

                if (DateTime.UtcNow < entry.Expire)
                    return entry.DomainControllers.OrderBy(_ => Random.Shared.Next()).ToList();

                _cache.TryRemove(KeyValuePair.Create(domain, lazy));
            }
        }

        private async Task<CacheEntry> DiscoverAsync(string domain)
        {
            using var cts = new CancellationTokenSource(_discoveryTimeout);

            var hosts = new List<string>();

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain, cts.Token);
                hosts.AddRange(addresses.Select(a => a.ToString()));
            }
            catch
            {
                // Sem resolução DNS: tenta o próprio nome informado.
            }

            if (hosts.Count == 0)
                hosts.Add(domain);

            var probes = await Task.WhenAll(hosts.Select(async host =>
            {
                await _probeLimiter.WaitAsync(cts.Token);
                try
                {
                    return (Host: host, Reachable: await IsReachableAsync(host, cts.Token));
                }
                finally
                {
                    _probeLimiter.Release();
                }
            }));

            var reachable = probes.Where(p => p.Reachable).Select(p => p.Host).ToList();

            return new CacheEntry(DateTime.UtcNow.Add(CacheDuration), reachable.Count > 0 ? reachable : hosts);
        }

        private static async Task<bool> IsReachableAsync(string host, CancellationToken ct)
        {
            try
            {
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(ProbeTimeout);

                await tcp.ConnectAsync(host, 389, cts.Token);
                return tcp.Connected;
            }
            catch
            {
                return false;
            }
        }
    }
}
