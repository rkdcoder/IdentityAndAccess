using IdentityAndAccess.Identity.Application.Ports.Out;
using IdentityAndAccess.Identity.Domain.Features.Auth.Entities;
using System.Collections.Concurrent;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory
{
    public sealed class ActiveDirectoryUsersGateway : IActiveDirectoryUsersGateway
    {
        private static readonly ConcurrentDictionary<string, Lazy<Task<CacheEntry>>> _dcCache = new();
        private static readonly ConcurrentDictionary<string, Lazy<Task<TimeSpan>>> _pwdPolicyCache = new();

        private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);
        private static readonly SemaphoreSlim _healthCheckLimiter = new(5);

        private sealed class CacheEntry
        {
            public DateTime Expire { get; init; }
            public List<string> DCs { get; init; } = new();
        }

        public async Task<IReadOnlyList<AdUserDetails>> GetAllUsersAsync(string domain, string? samAccountName, CancellationToken ct)
        {
            var domainControllers = await ResolveDomainControllersAsync(domain, ct);
            var maxPwdAge = await GetDomainMaxPasswordAge(domain, ct);

            Exception? lastError = null;

            foreach (var dc in domainControllers)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    return await Task.Run(() =>
                    {
                        var users = new List<AdUserDetails>();

                        string path = $"LDAP://{dc}";

                        using var rootEntry = new DirectoryEntry(path);
                        using var searcher = new DirectorySearcher(rootEntry);

                        string filter = "(&(objectCategory=person)(objectClass=user)";

                        if (!string.IsNullOrWhiteSpace(samAccountName))
                        {
                            var safeSamAccountName = samAccountName.Replace("\\", "\\5c")
                                                                   .Replace("*", "\\2a")
                                                                   .Replace("(", "\\28")
                                                                   .Replace(")", "\\29")
                                                                   .Replace("\0", "\\00");

                            filter += $"(sAMAccountName={safeSamAccountName})";
                        }

                        filter += ")";

                        searcher.Filter = filter;
                        searcher.PageSize = 1000;
                        searcher.ReferralChasing = ReferralChasingOption.None;

                        using var results = searcher.FindAll();

                        foreach (SearchResult result in results)
                        {
                            ct.ThrowIfCancellationRequested();

                            using var entry = result.GetDirectoryEntry();

                            var uac = GetIntProp(entry, "userAccountControl");
                            var pwdLastSet = ReadFileTime(entry, "pwdLastSet");

                            bool neverExpires = (uac & 0x10000) != 0;
                            bool mustChange = pwdLastSet == null || pwdLastSet.Value == DateTime.MinValue;

                            DateTime? expirationDate = null;
                            bool isExpired = false;

                            if (!neverExpires && pwdLastSet.HasValue)
                            {
                                if (maxPwdAge > TimeSpan.Zero)
                                {
                                    expirationDate = pwdLastSet.Value.Add(maxPwdAge);
                                    isExpired = expirationDate <= DateTime.UtcNow;
                                }
                            }

                            var userDetail = new AdUserDetails
                            {
                                SAMAccountName = GetProp(entry, "sAMAccountName"),
                                GivenName = GetProp(entry, "givenName"),
                                Initials = GetProp(entry, "initials"),
                                Sn = GetProp(entry, "sn"),
                                DisplayName = GetProp(entry, "displayName"),
                                Cn = GetProp(entry, "cn"),
                                Description = GetProp(entry, "description"),

                                WhenCreated = ReadDate(entry, "whenCreated"),
                                WhenChanged = ReadDate(entry, "whenChanged"),

                                PhysicalDeliveryOfficeName = GetProp(entry, "physicalDeliveryOfficeName"),
                                TelephoneNumber = GetProp(entry, "telephoneNumber"),
                                OtherTelephone = GetProp(entry, "otherTelephone"),

                                Mail = GetProp(entry, "mail"),
                                MailNickname = GetProp(entry, "mailNickname"),
                                MailAddress = GetProp(entry, "mailAddress"),

                                Ou = GetOrganizationalUnit(entry),

                                StreetAddress = GetProp(entry, "streetAddress"),
                                PostOfficeBox = GetProp(entry, "postOfficeBox"),
                                Street = GetProp(entry, "street"),

                                L = GetProp(entry, "l"),
                                St = GetProp(entry, "st"),
                                PostalCode = GetProp(entry, "postalCode"),
                                PostalAddress = GetProp(entry, "postalAddress"),

                                Co = GetProp(entry, "co"),
                                C = GetProp(entry, "c"),
                                CountryCode = GetIntProp(entry, "countryCode"),

                                UserPrincipalName = GetProp(entry, "userPrincipalName"),

                                PwdLastSet = pwdLastSet,
                                MaxPwdAge = ReadFileTime(entry, "maxPwdAge"),

                                HomePhone = GetProp(entry, "homePhone"),
                                OtherHomePhone = GetProp(entry, "otherHomePhone"),

                                Mobile = GetProp(entry, "mobile"),
                                OtherMobile = GetProp(entry, "otherMobile"),

                                FacsimileTelephoneNumber = GetProp(entry, "facsimileTelephoneNumber"),
                                OtherFacsimileTelephoneNumber = GetProp(entry, "otherFacsimileTelephoneNumber"),

                                IpPhone = GetProp(entry, "ipPhone"),
                                OtherIpPhone = GetProp(entry, "otherIpPhone"),

                                Info = GetProp(entry, "info"),
                                Title = GetProp(entry, "title"),
                                Department = GetProp(entry, "department"),
                                Company = GetProp(entry, "company"),

                                Manager = GetProp(entry, "manager"),
                                ManagedBy = GetProp(entry, "managedBy"),

                                DirectReports = GetMulti(entry, "directReports").ToList(),

                                DistinguishedName = GetProp(entry, "distinguishedName"),
                                CanonicalName = GetProp(entry, "canonicalName"),

                                MemberOf = GetMulti(entry, "memberOf").ToList(),

                                AltRecipient = GetProp(entry, "altRecipient"),

                                ProxyAddresses = GetMulti(entry, "proxyAddresses").ToList(),
                                TargetAddress = GetProp(entry, "targetAddress"),
                                ProtocolSettings = GetProp(entry, "protocolSettings"),

                                AccountNameHistory = GetProp(entry, "accountNameHistory"),

                                HomePostalAddress = GetProp(entry, "homePostalAddress"),

                                ApplicationName = GetProp(entry, "applicationName"),
                                AssetNumber = GetProp(entry, "assetNumber"),
                                Assistant = GetProp(entry, "assistant"),
                                AttributeDisplayNames = GetProp(entry, "attributeDisplayNames"),

                                BadPasswordTime = ReadFileTime(entry, "badPasswordTime"),
                                BadPwdCount = GetProp(entry, "badPwdCount"),

                                BuildingName = GetProp(entry, "buildingName"),
                                BusinessCategory = GetProp(entry, "businessCategory"),
                                CarLicense = GetProp(entry, "carLicense"),

                                ClassDisplayName = GetProp(entry, "classDisplayName"),

                                CreateTimeStamp = GetProp(entry, "createTimeStamp"),
                                CreationTime = ReadDate(entry, "creationTime"),

                                DepartmentNumber = GetProp(entry, "departmentNumber"),
                                Division = GetProp(entry, "division"),

                                DriverName = GetProp(entry, "driverName"),

                                EmployeeID = GetProp(entry, "employeeID"),
                                EmployeeNumber = GetProp(entry, "employeeNumber"),
                                EmployeeType = GetProp(entry, "employeeType"),

                                ExtensionName = GetProp(entry, "extensionName"),

                                FriendlyNames = GetProp(entry, "friendlyNames"),
                                GlobalAddressList = GetProp(entry, "globalAddressList"),

                                Keywords = GetProp(entry, "keywords"),

                                LastBackupRestorationTime = ReadDate(entry, "lastBackupRestorationTime"),
                                LastLogoff = ReadFileTime(entry, "lastLogoff"),
                                LastLogon = ReadFileTime(entry, "lastLogon"),
                                LastLogonTimestamp = ReadFileTime(entry, "lastLogonTimestamp"),

                                LastSetTime = ReadDate(entry, "lastSetTime"),

                                Location = GetProp(entry, "location"),

                                LockoutDuration = ReadFileTime(entry, "lockoutDuration"),
                                LockoutTime = ReadFileTime(entry, "lockoutTime"),

                                LogonCount = GetIntProp(entry, "logonCount"),

                                NCName = GetProp(entry, "nCName"),

                                OperatingSystem = GetProp(entry, "operatingSystem"),
                                OperatingSystemServicePack = GetProp(entry, "operatingSystemServicePack"),
                                OperatingSystemVersion = GetProp(entry, "operatingSystemVersion"),

                                OptionDescription = GetProp(entry, "optionDescription"),

                                O = GetProp(entry, "o"),

                                OtherMailbox = GetProp(entry, "otherMailbox"),

                                MiddleName = GetProp(entry, "middleName"),

                                Owner = GetProp(entry, "owner"),

                                PersonalTitle = GetProp(entry, "personalTitle"),

                                Name = GetProp(entry, "name"),

                                ServicePrincipalName = GetProp(entry, "servicePrincipalName"),

                                UPNSuffixes = GetProp(entry, "uPNSuffixes"),

                                PrimaryGroupID = GetIntProp(entry, "primaryGroupID").ToString(),
                                PrimaryGroupDescription = PrimaryGroupIDDetail(GetIntProp(entry, "primaryGroupID")),

                                PasswordExpirationDate = expirationDate,
                                IsPasswordExpired = isExpired,
                                PasswordNeverExpires = neverExpires,
                                MustChangePassword = mustChange,

                                UserAccountControl = uac.ToString(),
                                UserAccountControlValues = UserAccountControlPropsDetail(
                                    uac,
                                    isExpired,
                                    neverExpires,
                                    mustChange
                                )
                            };

                            users.Add(userDetail);
                        }

                        return (IReadOnlyList<AdUserDetails>)users;

                    }, ct);
                }
                catch (Exception ex)
                {
                    lastError = ex;
                }
            }

            throw new InvalidOperationException($"Falha ao extrair usuários: {lastError?.Message}", lastError);
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

        private async Task<List<string>> ResolveDomainControllersAsync(string domain, CancellationToken ct)
        {
            if (IPAddress.TryParse(domain, out _))
                return new List<string> { domain };

            var hosts = new List<string>();

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain, ct);
                hosts.AddRange(addresses.Select(a => a.ToString()));
            }
            catch { }

            if (hosts.Count == 0)
                hosts.Add(domain);

            return hosts;
        }

        private static string? GetProp(DirectoryEntry entry, string name)
        {
            try { return entry.Properties[name]?.Value?.ToString(); }
            catch { return null; }
        }

        private static int GetIntProp(DirectoryEntry entry, string name)
        {
            try
            {
                var val = entry.Properties[name]?.Value;
                if (val is int i) return i;
                if (int.TryParse(val?.ToString(), out int parsed)) return parsed;
                return 0;
            }
            catch { return 0; }
        }

        private static IEnumerable<string> GetMulti(DirectoryEntry entry, string name)
        {
            try
            {
                var col = entry.Properties[name];
                if (col == null || col.Count == 0) yield break;

                foreach (var item in col)
                    if (item != null)
                        yield return item.ToString()!;
            }
            finally { }
        }

        private static string? GetOrganizationalUnit(DirectoryEntry entry)
        {
            try
            {
                var dn = GetProp(entry, "distinguishedName");
                if (string.IsNullOrEmpty(dn)) return null;

                var match = Regex.Match(dn, @"OU=(.*?),");
                return match.Success ? match.Groups[1].Value : null;
            }
            catch { return null; }
        }

        private static DateTime? ReadDate(DirectoryEntry entry, string name)
        {
            try
            {
                var v = entry.Properties[name]?.Value;
                if (v is DateTime d) return DateTime.SpecifyKind(d, DateTimeKind.Utc);
                if (DateTime.TryParse(v?.ToString(), out var parsed)) return parsed.ToUniversalTime();
                return null;
            }
            catch { return null; }
        }

        private static DateTime? ReadFileTime(DirectoryEntry entry, string name)
        {
            try
            {
                var value = entry.Properties[name]?.Value;
                if (value == null) return null;

                if (value is DateTime dt) return dt;

                if (value is long l)
                    return l == 0 || l == 9223372036854775807 ? null : DateTime.FromFileTimeUtc(l);

                var type = value.GetType();

                if (type.Name == "__ComObject")
                {
                    var high = (int)type.InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, value, null)!;
                    var low = (int)type.InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, value, null)!;
                    long combined = ((long)high << 32) + (uint)low;

                    if (combined == 0 || combined == 9223372036854775807) return null;
                    return DateTime.FromFileTimeUtc(combined);
                }

                return null;
            }
            catch { return null; }
        }

        private static string PrimaryGroupIDDetail(int groupId)
        {
            return groupId switch
            {
                512 => "Domain Admins",
                513 => "Domain Users",
                514 => "Domain Guests",
                515 => "Domain Computers",
                516 => "Domain Controllers",
                _ => $"Group {groupId}"
            };
        }

        private static List<string> UserAccountControlPropsDetail(
            int uac,
            bool isExpired,
            bool neverExpires,
            bool mustChange)
        {
            var flags = new List<string>();

            if ((uac & 2) != 0) flags.Add("AccountDisabled");
            if ((uac & 8) != 0) flags.Add("HomeDirectoryRequired");
            if ((uac & 16) != 0) flags.Add("Lockout");
            if ((uac & 32) != 0) flags.Add("PasswordNotRequired");
            if ((uac & 64) != 0) flags.Add("PasswordCannotChange");
            if ((uac & 512) != 0) flags.Add("NormalAccount");

            if (neverExpires)
                flags.Add("PasswordNeverExpires");

            if (mustChange)
                flags.Add("MustChangePassword");

            if (isExpired)
                flags.Add("PasswordExpired");

            return flags;
        }
    }
}