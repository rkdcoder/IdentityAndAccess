using IdentityAndAccess.Api.Exceptions;
using IdentityAndAccess.Api.Models;
using IdentityAndAccess.Api.Options;
using IdentityAndAccess.Api.Services.ActiveDirectory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.DirectoryServices;
using System.Text.RegularExpressions;

namespace IdentityAndAccess.Api.Services
{
    public sealed class ActiveDirectoryUsersService : IActiveDirectoryUsersService
    {
        private const int UacPasswordNeverExpires = 0x10000;

        private readonly DirectoryServicesOptions _opts;
        private readonly DomainControllerResolver _resolver;
        private readonly PasswordPolicyReader _passwordPolicy;
        private readonly ILogger<ActiveDirectoryUsersService> _logger;

        public ActiveDirectoryUsersService(
            IOptions<DirectoryServicesOptions> opts,
            DomainControllerResolver resolver,
            PasswordPolicyReader passwordPolicy,
            ILogger<ActiveDirectoryUsersService> logger)
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

        // Atributos lidos de cada usuário. Trazê-los na própria busca evita uma ida ao servidor por usuário
        // (GetDirectoryEntry) e o tráfego dos demais atributos.
        private static readonly string[] UserProperties =
        {
            "accountNameHistory",
            "altRecipient",
            "applicationName",
            "assetNumber",
            "assistant",
            "attributeDisplayNames",
            "badPasswordTime",
            "badPwdCount",
            "buildingName",
            "businessCategory",
            "c",
            "canonicalName",
            "carLicense",
            "classDisplayName",
            "cn",
            "co",
            "company",
            "countryCode",
            "createTimeStamp",
            "creationTime",
            "department",
            "departmentNumber",
            "description",
            "directReports",
            "displayName",
            "distinguishedName",
            "division",
            "driverName",
            "employeeID",
            "employeeNumber",
            "employeeType",
            "extensionName",
            "facsimileTelephoneNumber",
            "friendlyNames",
            "givenName",
            "globalAddressList",
            "homePhone",
            "homePostalAddress",
            "info",
            "initials",
            "ipPhone",
            "keywords",
            "l",
            "lastBackupRestorationTime",
            "lastLogoff",
            "lastLogon",
            "lastLogonTimestamp",
            "lastSetTime",
            "location",
            "lockoutDuration",
            "lockoutTime",
            "logonCount",
            "mail",
            "mailAddress",
            "mailNickname",
            "managedBy",
            "manager",
            "maxPwdAge",
            "memberOf",
            "middleName",
            "mobile",
            "name",
            "nCName",
            "o",
            "operatingSystem",
            "operatingSystemServicePack",
            "operatingSystemVersion",
            "optionDescription",
            "otherFacsimileTelephoneNumber",
            "otherHomePhone",
            "otherIpPhone",
            "otherMailbox",
            "otherMobile",
            "otherTelephone",
            "owner",
            "personalTitle",
            "physicalDeliveryOfficeName",
            "postalAddress",
            "postalCode",
            "postOfficeBox",
            "primaryGroupID",
            "protocolSettings",
            "proxyAddresses",
            "pwdLastSet",
            "sAMAccountName",
            "servicePrincipalName",
            "sn",
            "st",
            "street",
            "streetAddress",
            "targetAddress",
            "telephoneNumber",
            "title",
            "uPNSuffixes",
            "userAccountControl",
            "userPrincipalName",
            "whenChanged",
            "whenCreated"
        };

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
            searcher.PropertiesToLoad.AddRange(UserProperties);

            if (_opts.TimeoutSeconds > 0)
                searcher.ClientTimeout = TimeSpan.FromSeconds(_opts.TimeoutSeconds);

            using var results = searcher.FindAll();

            foreach (SearchResult result in results)
            {
                ct.ThrowIfCancellationRequested();

                var uac = SearchResultReader.GetInt(result, "userAccountControl");
                var pwdLastSet = SearchResultReader.GetFileTime(result, "pwdLastSet");

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
                    SAMAccountName = SearchResultReader.GetString(result, "sAMAccountName"),
                    GivenName = SearchResultReader.GetString(result, "givenName"),
                    Initials = SearchResultReader.GetString(result, "initials"),
                    Sn = SearchResultReader.GetString(result, "sn"),
                    DisplayName = SearchResultReader.GetString(result, "displayName"),
                    Cn = SearchResultReader.GetString(result, "cn"),
                    Description = SearchResultReader.GetString(result, "description"),

                    WhenCreated = SearchResultReader.GetDate(result, "whenCreated"),
                    WhenChanged = SearchResultReader.GetDate(result, "whenChanged"),

                    PhysicalDeliveryOfficeName = SearchResultReader.GetString(result, "physicalDeliveryOfficeName"),
                    TelephoneNumber = SearchResultReader.GetString(result, "telephoneNumber"),
                    OtherTelephone = SearchResultReader.GetString(result, "otherTelephone"),

                    Mail = SearchResultReader.GetString(result, "mail"),
                    MailNickname = SearchResultReader.GetString(result, "mailNickname"),
                    MailAddress = SearchResultReader.GetString(result, "mailAddress"),

                    Ou = GetOrganizationalUnit(result),

                    StreetAddress = SearchResultReader.GetString(result, "streetAddress"),
                    PostOfficeBox = SearchResultReader.GetString(result, "postOfficeBox"),
                    Street = SearchResultReader.GetString(result, "street"),

                    L = SearchResultReader.GetString(result, "l"),
                    St = SearchResultReader.GetString(result, "st"),
                    PostalCode = SearchResultReader.GetString(result, "postalCode"),
                    PostalAddress = SearchResultReader.GetString(result, "postalAddress"),

                    Co = SearchResultReader.GetString(result, "co"),
                    C = SearchResultReader.GetString(result, "c"),
                    CountryCode = SearchResultReader.GetInt(result, "countryCode"),

                    UserPrincipalName = SearchResultReader.GetString(result, "userPrincipalName"),

                    PwdLastSet = pwdLastSet,
                    MaxPwdAge = SearchResultReader.GetFileTime(result, "maxPwdAge"),

                    HomePhone = SearchResultReader.GetString(result, "homePhone"),
                    OtherHomePhone = SearchResultReader.GetString(result, "otherHomePhone"),

                    Mobile = SearchResultReader.GetString(result, "mobile"),
                    OtherMobile = SearchResultReader.GetString(result, "otherMobile"),

                    FacsimileTelephoneNumber = SearchResultReader.GetString(result, "facsimileTelephoneNumber"),
                    OtherFacsimileTelephoneNumber = SearchResultReader.GetString(result, "otherFacsimileTelephoneNumber"),

                    IpPhone = SearchResultReader.GetString(result, "ipPhone"),
                    OtherIpPhone = SearchResultReader.GetString(result, "otherIpPhone"),

                    Info = SearchResultReader.GetString(result, "info"),
                    Title = SearchResultReader.GetString(result, "title"),
                    Department = SearchResultReader.GetString(result, "department"),
                    Company = SearchResultReader.GetString(result, "company"),

                    Manager = SearchResultReader.GetString(result, "manager"),
                    ManagedBy = SearchResultReader.GetString(result, "managedBy"),

                    DirectReports = SearchResultReader.GetMulti(result, "directReports").ToList(),

                    DistinguishedName = SearchResultReader.GetString(result, "distinguishedName"),
                    CanonicalName = SearchResultReader.GetString(result, "canonicalName"),

                    MemberOf = SearchResultReader.GetMulti(result, "memberOf").ToList(),

                    AltRecipient = SearchResultReader.GetString(result, "altRecipient"),

                    ProxyAddresses = SearchResultReader.GetMulti(result, "proxyAddresses").ToList(),
                    TargetAddress = SearchResultReader.GetString(result, "targetAddress"),
                    ProtocolSettings = SearchResultReader.GetString(result, "protocolSettings"),

                    AccountNameHistory = SearchResultReader.GetString(result, "accountNameHistory"),

                    HomePostalAddress = SearchResultReader.GetString(result, "homePostalAddress"),

                    ApplicationName = SearchResultReader.GetString(result, "applicationName"),
                    AssetNumber = SearchResultReader.GetString(result, "assetNumber"),
                    Assistant = SearchResultReader.GetString(result, "assistant"),
                    AttributeDisplayNames = SearchResultReader.GetString(result, "attributeDisplayNames"),

                    BadPasswordTime = SearchResultReader.GetFileTime(result, "badPasswordTime"),
                    BadPwdCount = SearchResultReader.GetString(result, "badPwdCount"),

                    BuildingName = SearchResultReader.GetString(result, "buildingName"),
                    BusinessCategory = SearchResultReader.GetString(result, "businessCategory"),
                    CarLicense = SearchResultReader.GetString(result, "carLicense"),

                    ClassDisplayName = SearchResultReader.GetString(result, "classDisplayName"),

                    CreateTimeStamp = SearchResultReader.GetString(result, "createTimeStamp"),
                    CreationTime = SearchResultReader.GetDate(result, "creationTime"),

                    DepartmentNumber = SearchResultReader.GetString(result, "departmentNumber"),
                    Division = SearchResultReader.GetString(result, "division"),

                    DriverName = SearchResultReader.GetString(result, "driverName"),

                    EmployeeID = SearchResultReader.GetString(result, "employeeID"),
                    EmployeeNumber = SearchResultReader.GetString(result, "employeeNumber"),
                    EmployeeType = SearchResultReader.GetString(result, "employeeType"),

                    ExtensionName = SearchResultReader.GetString(result, "extensionName"),

                    FriendlyNames = SearchResultReader.GetString(result, "friendlyNames"),
                    GlobalAddressList = SearchResultReader.GetString(result, "globalAddressList"),

                    Keywords = SearchResultReader.GetString(result, "keywords"),

                    LastBackupRestorationTime = SearchResultReader.GetDate(result, "lastBackupRestorationTime"),
                    LastLogoff = SearchResultReader.GetFileTime(result, "lastLogoff"),
                    LastLogon = SearchResultReader.GetFileTime(result, "lastLogon"),
                    LastLogonTimestamp = SearchResultReader.GetFileTime(result, "lastLogonTimestamp"),

                    LastSetTime = SearchResultReader.GetDate(result, "lastSetTime"),

                    Location = SearchResultReader.GetString(result, "location"),

                    LockoutDuration = SearchResultReader.GetFileTime(result, "lockoutDuration"),
                    LockoutTime = SearchResultReader.GetFileTime(result, "lockoutTime"),

                    LogonCount = SearchResultReader.GetInt(result, "logonCount"),

                    NCName = SearchResultReader.GetString(result, "nCName"),

                    OperatingSystem = SearchResultReader.GetString(result, "operatingSystem"),
                    OperatingSystemServicePack = SearchResultReader.GetString(result, "operatingSystemServicePack"),
                    OperatingSystemVersion = SearchResultReader.GetString(result, "operatingSystemVersion"),

                    OptionDescription = SearchResultReader.GetString(result, "optionDescription"),

                    O = SearchResultReader.GetString(result, "o"),

                    OtherMailbox = SearchResultReader.GetString(result, "otherMailbox"),

                    MiddleName = SearchResultReader.GetString(result, "middleName"),

                    Owner = SearchResultReader.GetString(result, "owner"),

                    PersonalTitle = SearchResultReader.GetString(result, "personalTitle"),

                    Name = SearchResultReader.GetString(result, "name"),

                    ServicePrincipalName = SearchResultReader.GetString(result, "servicePrincipalName"),

                    UPNSuffixes = SearchResultReader.GetString(result, "uPNSuffixes"),

                    PrimaryGroupID = SearchResultReader.GetInt(result, "primaryGroupID").ToString(),
                    PrimaryGroupDescription = PrimaryGroupIDDetail(SearchResultReader.GetInt(result, "primaryGroupID")),

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

        private static string? GetOrganizationalUnit(SearchResult result)
        {
            var dn = SearchResultReader.GetString(result, "distinguishedName");
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