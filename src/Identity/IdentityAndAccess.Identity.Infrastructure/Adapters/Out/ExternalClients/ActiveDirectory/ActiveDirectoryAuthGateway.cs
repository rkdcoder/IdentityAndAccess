using IdentityAndAccess.Identity.Application.Ports.Out;
using IdentityAndAccess.Identity.Domain.Features.Auth.Entities;
using Microsoft.Extensions.Options;
using Platform.Identity.Abstractions.Options;
using System.Collections.Concurrent;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Net.Sockets;

namespace IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory;

public sealed class ActiveDirectoryAuthGateway : IActiveDirectoryAuthGateway
{
    private readonly DirectoryServicesOptions _opts;

    private static readonly ConcurrentDictionary<string, Lazy<Task<CacheEntry>>> _dcCache = new();

    private static readonly ConcurrentDictionary<string, Lazy<Task<TimeSpan>>> _pwdPolicyCache = new();

    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);

    private static readonly SemaphoreSlim _healthCheckLimiter = new(5);

    private sealed class CacheEntry
    {
        public DateTime Expire { get; init; }
        public List<string> DCs { get; init; } = new();
    }

    public ActiveDirectoryAuthGateway(IOptions<DirectoryServicesOptions> opts)
        => _opts = opts.Value;

    public async Task<(bool Success, string Message, AdUser? User)> ValidateAndGetAsync(
        string domain,
        string username,
        string password,
        CancellationToken ct)
    {
        var ctxOptions = ParseContextOptions(_opts.ContextOptions);

        var domainControllers = await ResolveDomainControllersAsync(domain, ct);

        Exception? lastError = null;

        foreach (var dc in domainControllers)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                using var context = new PrincipalContext(
                    ContextType.Domain,
                    dc,
                    null,
                    ctxOptions);

                using var user = UserPrincipal.FindByIdentity(context, username);

                if (user is null)
                    return (false, "Usuário não encontrado no domínio informado.", null);

                var ok = context.ValidateCredentials(username, password, ctxOptions);

                var entry = (DirectoryEntry?)user.GetUnderlyingObject();

                var pwdLastSet = ReadFileTime(entry, "pwdLastSet");
                var uac = GetUserAccountControl(entry);

                bool neverExpires = (uac & 0x10000) != 0;
                bool mustChange = pwdLastSet == null || pwdLastSet.Value == DateTime.MinValue;

                var maxPwdAge = await GetDomainMaxPasswordAge(domain, ct);

                DateTime? expirationDate = null;
                bool isExpired = false;

                if (!neverExpires && pwdLastSet.HasValue && maxPwdAge > TimeSpan.Zero)
                {
                    expirationDate = pwdLastSet.Value.Add(maxPwdAge);
                    isExpired = expirationDate <= DateTime.UtcNow;
                }

                if (!ok)
                {
                    if (mustChange)
                        return (false, "Senha deve ser alterada antes do primeiro acesso.", null);

                    if (isExpired)
                        return (false, "Senha expirada.", null);

                    return (false, "Credenciais inválidas.", null);
                }

                if (!IPAddress.TryParse(domain, out _))
                {
                    var expectedDomainDn = string.Join(",",
                        domain.Split('.', StringSplitOptions.RemoveEmptyEntries)
                              .Select(p => $"DC={p}"));

                    var userDn = user.DistinguishedName;

                    if (string.IsNullOrWhiteSpace(userDn) ||
                        !userDn.Contains(expectedDomainDn, StringComparison.OrdinalIgnoreCase))
                    {
                        return (false,
                            "Acesso negado: credenciais pertencem a outro domínio.",
                            null);
                    }
                }

                var adUser = new AdUser
                {
                    DisplayName = user.DisplayName,
                    UserPrincipalName = user.UserPrincipalName,
                    SamAccountName = user.SamAccountName,
                    DistinguishedName = user.DistinguishedName,
                    Email = user.EmailAddress,
                    GivenName = user.GivenName,
                    Surname = user.Surname,
                    MiddleName = GetProp(entry, "middleName"),
                    Department = GetProp(entry, "department"),
                    Company = GetProp(entry, "company"),
                    Title = GetProp(entry, "title"),
                    Manager = GetProp(entry, "manager"),
                    Office = GetProp(entry, "physicalDeliveryOfficeName"),
                    StreetAddress = GetProp(entry, "streetAddress"),
                    City = GetProp(entry, "l"),
                    State = GetProp(entry, "st"),
                    PostalCode = GetProp(entry, "postalCode"),
                    CountryCode = GetProp(entry, "countryCode"),
                    Telephone = user.VoiceTelephoneNumber ?? GetProp(entry, "telephoneNumber"),
                    Mobile = GetProp(entry, "mobile"),
                    Enabled = user.Enabled,
                    Sid = user.Sid?.Value,
                    AccountExpirationDate = user.AccountExpirationDate,
                    LastLogon = ReadFileTime(entry, "lastLogonTimestamp"),
                    WhenCreated = ReadDate(entry, "whenCreated"),
                    WhenChanged = ReadDate(entry, "whenChanged"),
                    PasswordNeverExpires = neverExpires,
                    PasswordNotRequired = GetUserFlag(entry, 0x0020),
                    PasswordLastSet = pwdLastSet,
                    MemberOf = GetMulti(entry, "memberOf")
                };

                return (true, "Credenciais válidas.", adUser);
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }

        return (false, $"Falha ao contactar DCs: {lastError?.Message}", null);
    }

    private async Task<TimeSpan> GetDomainMaxPasswordAge(string domain, CancellationToken ct)
    {
        var lazy = _pwdPolicyCache.GetOrAdd(domain,
            d => new Lazy<Task<TimeSpan>>(() => Task.Run(() =>
            {
                using var entry = new DirectoryEntry($"LDAP://{domain}");
                var value = entry.Properties["maxPwdAge"]?.Value;

                if (value == null)
                    return TimeSpan.Zero;

                long ticks;

                if (value is long l)
                    ticks = l;
                else
                {
                    var type = value.GetType();
                    var high = (int)type.InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, value, null)!;
                    var low = (int)type.InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, value, null)!;
                    ticks = ((long)high << 32) + (uint)low;
                }

                if (ticks == 0 || ticks == long.MinValue)
                    return TimeSpan.Zero;

                return TimeSpan.FromTicks(Math.Abs(ticks));

            }, ct)));

        return await lazy.Value;
    }

    private static int GetUserAccountControl(DirectoryEntry? entry)
    {
        try
        {
            var val = entry?.Properties["userAccountControl"]?.Value;

            if (val is int i) return i;

            if (int.TryParse(val?.ToString(), out var parsed))
                return parsed;

            return 0;
        }
        catch
        {
            return 0;
        }
    }

    private async Task<List<string>> ResolveDomainControllersAsync(string domain, CancellationToken ct)
    {
        if (IPAddress.TryParse(domain, out _))
        {
            return new List<string> { domain };
        }

        while (true)
        {
            var lazy = _dcCache.GetOrAdd(domain,
                d => new Lazy<Task<CacheEntry>>(() => DiscoverDomainControllersAsync(d, ct)));

            try
            {
                var entry = await lazy.Value;

                if (DateTime.UtcNow < entry.Expire)
                {
                    return entry.DCs.OrderBy(_ => Random.Shared.Next()).ToList();
                }

                _dcCache.TryRemove(domain, out _);
            }
            catch
            {
                _dcCache.TryRemove(domain, out _);
                throw;
            }
        }
    }

    private async Task<CacheEntry> DiscoverDomainControllersAsync(string domain, CancellationToken ct)
    {
        var hosts = new List<string>();

        try
        {
            var srvRecords = await Dns.GetHostAddressesAsync(domain, ct);

            foreach (var addr in srvRecords)
                hosts.Add(addr.ToString());
        }
        catch
        {
        }

        if (hosts.Count == 0)
            hosts.Add(domain);

        var tasks = hosts.Select(async host =>
        {
            await _healthCheckLimiter.WaitAsync(ct);

            try
            {
                bool reachable = await IsDomainControllerReachableAsync(host, ct);
                return new { Host = host, Reachable = reachable };
            }
            finally
            {
                _healthCheckLimiter.Release();
            }
        });

        var results = await Task.WhenAll(tasks);

        var reachable = results
            .Where(r => r.Reachable)
            .Select(r => r.Host)
            .ToList();

        var finalList = reachable.Count > 0 ? reachable : hosts;

        return new CacheEntry
        {
            Expire = DateTime.UtcNow.Add(CacheDuration),
            DCs = finalList
        };
    }

    private static async Task<bool> IsDomainControllerReachableAsync(string host, CancellationToken ct)
    {
        try
        {
            using var tcp = new TcpClient();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(1));

            await tcp.ConnectAsync(host, 389, timeoutCts.Token);

            return tcp.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static ContextOptions ParseContextOptions(string input)
        => Enum.TryParse<ContextOptions>(input, true, out var result)
           ? result
           : ContextOptions.Negotiate;

    private static string? GetProp(DirectoryEntry? entry, string name)
    {
        try { return entry?.Properties[name]?.Value?.ToString(); }
        catch { return null; }
    }

    private static IReadOnlyList<string> GetMulti(DirectoryEntry? entry, string name)
    {
        try
        {
            var col = entry?.Properties[name];

            if (col is null || col.Count == 0)
                return Array.Empty<string>();

            var list = new List<string>(col.Count);

            foreach (var item in col)
                if (item != null)
                    list.Add(item.ToString()!);

            return list;
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static DateTime? ReadFileTime(DirectoryEntry? entry, string name)
    {
        try
        {
            var v = entry?.Properties[name]?.Value;

            if (v is null)
                return null;

            if (v is long l)
                return l == 0 ? null : DateTime.FromFileTimeUtc(l);

            var type = v.GetType();

            if (type.Name == "__ComObject")
            {
                var high = (int)type.InvokeMember("HighPart",
                    System.Reflection.BindingFlags.GetProperty,
                    null, v, null)!;

                var low = (int)type.InvokeMember("LowPart",
                    System.Reflection.BindingFlags.GetProperty,
                    null, v, null)!;

                long combined = ((long)high << 32) + (uint)low;

                return combined == 0 ? null : DateTime.FromFileTimeUtc(combined);
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? ReadDate(DirectoryEntry? entry, string name)
    {
        try
        {
            var v = entry?.Properties[name]?.Value;

            if (v is DateTime d)
                return DateTime.SpecifyKind(d, DateTimeKind.Utc);

            if (DateTime.TryParse(v?.ToString(), out var parsed))
                return parsed.ToUniversalTime();

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static bool? GetUserFlag(DirectoryEntry? entry, int flag)
    {
        try
        {
            var v = entry?.Properties["userAccountControl"]?.Value;

            if (v is int i)
                return (i & flag) == flag;

            if (int.TryParse(v?.ToString(), out var parsed))
                return (parsed & flag) == flag;

            return null;
        }
        catch
        {
            return null;
        }
    }
}