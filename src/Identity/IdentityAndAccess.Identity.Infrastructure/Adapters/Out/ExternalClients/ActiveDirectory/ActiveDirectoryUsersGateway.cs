using IdentityAndAccess.Identity.Application.Exceptions;
using IdentityAndAccess.Identity.Application.Ports.Out;
using IdentityAndAccess.Identity.Domain.Features.Auth.Entities;
using IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Platform.Identity.Abstractions.Options;
using System.DirectoryServices;
using System.Text.RegularExpressions;

namespace IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory
{
    public sealed class ActiveDirectoryUsersGateway : IActiveDirectoryUsersGateway
    {
        private const int UacPasswordNeverExpires = 0x10000;

        private readonly DirectoryServicesOptions _opts;
        private readonly DomainControllerResolver _resolver;
        private readonly PasswordPolicyReader _passwordPolicy;
        private readonly ILogger<ActiveDirectoryUsersGateway> _logger;

        public ActiveDirectoryUsersGateway(
            IOptions<DirectoryServicesOptions> opts,
            DomainControllerResolver resolver,
            PasswordPolicyReader passwordPolicy,
            ILogger<ActiveDirectoryUsersGateway> logger)
        {
            _opts = opts.Value;
            _resolver = resolver;
            _passwordPolicy = passwordPolicy;
            _logger = logger;
        }

        public async Task<IReadOnlyList<AdUserDetails>> GetAllUsersAsync(string domain, string? samAccountName, CancellationToken ct)
        {
            var domainControllers = await _resolver.ResolveAsync(domain, ct);
            var maxPwdAge = await _passwordPolicy.GetMaxPasswordAgeAsync(domain, ct);

            Exception? lastError = null;

            foreach (var dc in domainControllers)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    return await Task.Run(() => SearchUsers(dc, samAccountName, maxPwdAge, ct), ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Falha ao listar usuários no controlador de domínio {DomainController} ({Domain}).", dc, domain);
                    lastError = ex;
                }
            }

            throw new DirectoryUnavailableException(domain, lastError);
        }

        private IReadOnlyList<AdUserDetails> SearchUsers(string dc, string? samAccountName, TimeSpan maxPwdAge, CancellationToken ct)
        {
            var users = new List<AdUserDetails>();

            using var rootEntry = new DirectoryEntry($"LDAP://{dc}");
            using var searcher = new DirectorySearcher(rootEntry);

            var filter = "(&(objectCategory=person)(objectClass=user)";

            if (!string.IsNullOrWhiteSpace(samAccountName))
                filter += $"(sAMAccountName={EscapeLdapFilterValue(samAccountName)})";

            filter += ")";

            searcher.Filter = filter;
            searcher.PageSize = 1000;
            searcher.ReferralChasing = ReferralChasingOption.None;

            if (_opts.TimeoutSeconds > 0)
                searcher.ClientTimeout = TimeSpan.FromSeconds(_opts.TimeoutSeconds);

            using var results = searcher.FindAll();

            foreach (SearchResult result in results)
            {
                ct.ThrowIfCancellationRequested();

                using var entry = result.GetDirectoryEntry();

                var uac = DirectoryEntryReader.GetInt(entry, "userAccountControl");
                var pwdLastSet = DirectoryEntryReader.GetFileTime(entry, "pwdLastSet");

                bool neverExpires = (uac & UacPasswordNeverExpires) != 0;
                bool mustChange = pwdLastSet == null || pwdLastSet.Value == DateTime.MinValue;

                DateTime? expirationDate = null;
                bool isExpired = false;

                if (!neverExpires && pwdLastSet.HasValue && maxPwdAge > TimeSpan.Zero)
                {
                    expirationDate = pwdLastSet.Value.Add(maxPwdAge);
                    isExpired = expirationDate <= DateTime.UtcNow;
                }

                var userDetail = new AdUserDetails
                {
                    SAMAccountName = DirectoryEntryReader.GetString(entry, "sAMAccountName"),
                    GivenName = DirectoryEntryReader.GetString(entry, "givenName"),
                    Initials = DirectoryEntryReader.GetString(entry, "initials"),
                    Sn = DirectoryEntryReader.GetString(entry, "sn"),
                    DisplayName = DirectoryEntryReader.GetString(entry, "displayName"),
                    Cn = DirectoryEntryReader.GetString(entry, "cn"),
                    Description = DirectoryEntryReader.GetString(entry, "description"),

                    WhenCreated = DirectoryEntryReader.GetDate(entry, "whenCreated"),
                    WhenChanged = DirectoryEntryReader.GetDate(entry, "whenChanged"),

                    PhysicalDeliveryOfficeName = DirectoryEntryReader.GetString(entry, "physicalDeliveryOfficeName"),
                    TelephoneNumber = DirectoryEntryReader.GetString(entry, "telephoneNumber"),
                    OtherTelephone = DirectoryEntryReader.GetString(entry, "otherTelephone"),

                    Mail = DirectoryEntryReader.GetString(entry, "mail"),
                    MailNickname = DirectoryEntryReader.GetString(entry, "mailNickname"),
                    MailAddress = DirectoryEntryReader.GetString(entry, "mailAddress"),

                    Ou = GetOrganizationalUnit(entry),

                    StreetAddress = DirectoryEntryReader.GetString(entry, "streetAddress"),
                    PostOfficeBox = DirectoryEntryReader.GetString(entry, "postOfficeBox"),
                    Street = DirectoryEntryReader.GetString(entry, "street"),

                    L = DirectoryEntryReader.GetString(entry, "l"),
                    St = DirectoryEntryReader.GetString(entry, "st"),
                    PostalCode = DirectoryEntryReader.GetString(entry, "postalCode"),
                    PostalAddress = DirectoryEntryReader.GetString(entry, "postalAddress"),

                    Co = DirectoryEntryReader.GetString(entry, "co"),
                    C = DirectoryEntryReader.GetString(entry, "c"),
                    CountryCode = DirectoryEntryReader.GetInt(entry, "countryCode"),

                    UserPrincipalName = DirectoryEntryReader.GetString(entry, "userPrincipalName"),

                    PwdLastSet = pwdLastSet,
                    MaxPwdAge = DirectoryEntryReader.GetFileTime(entry, "maxPwdAge"),

                    HomePhone = DirectoryEntryReader.GetString(entry, "homePhone"),
                    OtherHomePhone = DirectoryEntryReader.GetString(entry, "otherHomePhone"),

                    Mobile = DirectoryEntryReader.GetString(entry, "mobile"),
                    OtherMobile = DirectoryEntryReader.GetString(entry, "otherMobile"),

                    FacsimileTelephoneNumber = DirectoryEntryReader.GetString(entry, "facsimileTelephoneNumber"),
                    OtherFacsimileTelephoneNumber = DirectoryEntryReader.GetString(entry, "otherFacsimileTelephoneNumber"),

                    IpPhone = DirectoryEntryReader.GetString(entry, "ipPhone"),
                    OtherIpPhone = DirectoryEntryReader.GetString(entry, "otherIpPhone"),

                    Info = DirectoryEntryReader.GetString(entry, "info"),
                    Title = DirectoryEntryReader.GetString(entry, "title"),
                    Department = DirectoryEntryReader.GetString(entry, "department"),
                    Company = DirectoryEntryReader.GetString(entry, "company"),

                    Manager = DirectoryEntryReader.GetString(entry, "manager"),
                    ManagedBy = DirectoryEntryReader.GetString(entry, "managedBy"),

                    DirectReports = DirectoryEntryReader.GetMulti(entry, "directReports").ToList(),

                    DistinguishedName = DirectoryEntryReader.GetString(entry, "distinguishedName"),
                    CanonicalName = DirectoryEntryReader.GetString(entry, "canonicalName"),

                    MemberOf = DirectoryEntryReader.GetMulti(entry, "memberOf").ToList(),

                    AltRecipient = DirectoryEntryReader.GetString(entry, "altRecipient"),

                    ProxyAddresses = DirectoryEntryReader.GetMulti(entry, "proxyAddresses").ToList(),
                    TargetAddress = DirectoryEntryReader.GetString(entry, "targetAddress"),
                    ProtocolSettings = DirectoryEntryReader.GetString(entry, "protocolSettings"),

                    AccountNameHistory = DirectoryEntryReader.GetString(entry, "accountNameHistory"),

                    HomePostalAddress = DirectoryEntryReader.GetString(entry, "homePostalAddress"),

                    ApplicationName = DirectoryEntryReader.GetString(entry, "applicationName"),
                    AssetNumber = DirectoryEntryReader.GetString(entry, "assetNumber"),
                    Assistant = DirectoryEntryReader.GetString(entry, "assistant"),
                    AttributeDisplayNames = DirectoryEntryReader.GetString(entry, "attributeDisplayNames"),

                    BadPasswordTime = DirectoryEntryReader.GetFileTime(entry, "badPasswordTime"),
                    BadPwdCount = DirectoryEntryReader.GetString(entry, "badPwdCount"),

                    BuildingName = DirectoryEntryReader.GetString(entry, "buildingName"),
                    BusinessCategory = DirectoryEntryReader.GetString(entry, "businessCategory"),
                    CarLicense = DirectoryEntryReader.GetString(entry, "carLicense"),

                    ClassDisplayName = DirectoryEntryReader.GetString(entry, "classDisplayName"),

                    CreateTimeStamp = DirectoryEntryReader.GetString(entry, "createTimeStamp"),
                    CreationTime = DirectoryEntryReader.GetDate(entry, "creationTime"),

                    DepartmentNumber = DirectoryEntryReader.GetString(entry, "departmentNumber"),
                    Division = DirectoryEntryReader.GetString(entry, "division"),

                    DriverName = DirectoryEntryReader.GetString(entry, "driverName"),

                    EmployeeID = DirectoryEntryReader.GetString(entry, "employeeID"),
                    EmployeeNumber = DirectoryEntryReader.GetString(entry, "employeeNumber"),
                    EmployeeType = DirectoryEntryReader.GetString(entry, "employeeType"),

                    ExtensionName = DirectoryEntryReader.GetString(entry, "extensionName"),

                    FriendlyNames = DirectoryEntryReader.GetString(entry, "friendlyNames"),
                    GlobalAddressList = DirectoryEntryReader.GetString(entry, "globalAddressList"),

                    Keywords = DirectoryEntryReader.GetString(entry, "keywords"),

                    LastBackupRestorationTime = DirectoryEntryReader.GetDate(entry, "lastBackupRestorationTime"),
                    LastLogoff = DirectoryEntryReader.GetFileTime(entry, "lastLogoff"),
                    LastLogon = DirectoryEntryReader.GetFileTime(entry, "lastLogon"),
                    LastLogonTimestamp = DirectoryEntryReader.GetFileTime(entry, "lastLogonTimestamp"),

                    LastSetTime = DirectoryEntryReader.GetDate(entry, "lastSetTime"),

                    Location = DirectoryEntryReader.GetString(entry, "location"),

                    LockoutDuration = DirectoryEntryReader.GetFileTime(entry, "lockoutDuration"),
                    LockoutTime = DirectoryEntryReader.GetFileTime(entry, "lockoutTime"),

                    LogonCount = DirectoryEntryReader.GetInt(entry, "logonCount"),

                    NCName = DirectoryEntryReader.GetString(entry, "nCName"),

                    OperatingSystem = DirectoryEntryReader.GetString(entry, "operatingSystem"),
                    OperatingSystemServicePack = DirectoryEntryReader.GetString(entry, "operatingSystemServicePack"),
                    OperatingSystemVersion = DirectoryEntryReader.GetString(entry, "operatingSystemVersion"),

                    OptionDescription = DirectoryEntryReader.GetString(entry, "optionDescription"),

                    O = DirectoryEntryReader.GetString(entry, "o"),

                    OtherMailbox = DirectoryEntryReader.GetString(entry, "otherMailbox"),

                    MiddleName = DirectoryEntryReader.GetString(entry, "middleName"),

                    Owner = DirectoryEntryReader.GetString(entry, "owner"),

                    PersonalTitle = DirectoryEntryReader.GetString(entry, "personalTitle"),

                    Name = DirectoryEntryReader.GetString(entry, "name"),

                    ServicePrincipalName = DirectoryEntryReader.GetString(entry, "servicePrincipalName"),

                    UPNSuffixes = DirectoryEntryReader.GetString(entry, "uPNSuffixes"),

                    PrimaryGroupID = DirectoryEntryReader.GetInt(entry, "primaryGroupID").ToString(),
                    PrimaryGroupDescription = PrimaryGroupIDDetail(DirectoryEntryReader.GetInt(entry, "primaryGroupID")),

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

            return users;
        }

        private static string EscapeLdapFilterValue(string value)
            => value.Replace("\\", "\\5c")
                    .Replace("*", "\\2a")
                    .Replace("(", "\\28")
                    .Replace(")", "\\29")
                    .Replace("\0", "\\00");

        private static string? GetOrganizationalUnit(DirectoryEntry entry)
        {
            var dn = DirectoryEntryReader.GetString(entry, "distinguishedName");
            if (string.IsNullOrEmpty(dn)) return null;

            var match = Regex.Match(dn, @"OU=(.*?),");
            return match.Success ? match.Groups[1].Value : null;
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