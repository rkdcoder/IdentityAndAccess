
namespace IdentityAndAccess.Identity.Domain.Features.Auth.Entities
{
    public sealed class AdUserDetails
    {
        public string? SAMAccountName { get; init; }
        public string? GivenName { get; init; }
        public string? Initials { get; init; }
        public string? Sn { get; init; }
        public string? DisplayName { get; init; }
        public string? Cn { get; init; }
        public string? Description { get; init; }
        public DateTime? WhenCreated { get; init; }
        public DateTime? WhenChanged { get; init; }
        public string? PhysicalDeliveryOfficeName { get; init; }
        public string? TelephoneNumber { get; init; }
        public string? OtherTelephone { get; init; }
        public string? Mail { get; init; }
        public string? Ou { get; init; }
        public string? StreetAddress { get; init; }
        public string? PostOfficeBox { get; init; }
        public string? L { get; init; }
        public string? St { get; init; }
        public string? PostalCode { get; init; }
        public string? Co { get; init; }
        public string? C { get; init; }
        public int CountryCode { get; init; }
        public string? UserPrincipalName { get; init; }
        public DateTime? PwdLastSet { get; init; }
        public DateTime? PasswordExpirationDate { get; init; }
        public bool IsPasswordExpired { get; init; }
        public bool PasswordNeverExpires { get; init; }
        public bool MustChangePassword { get; init; }
        public DateTime? MaxPwdAge { get; init; }
        public string? HomePhone { get; init; }
        public string? OtherHomePhone { get; init; }
        public string? Mobile { get; init; }
        public string? OtherMobile { get; init; }
        public string? FacsimileTelephoneNumber { get; init; }
        public string? OtherFacsimileTelephoneNumber { get; init; }
        public string? IpPhone { get; init; }
        public string? OtherIpPhone { get; init; }
        public string? Info { get; init; }
        public string? Title { get; init; }
        public string? Department { get; init; }
        public string? Company { get; init; }
        public string? Manager { get; init; }
        public IReadOnlyList<string> DirectReports { get; init; } = Array.Empty<string>();
        public string? DistinguishedName { get; init; }
        public IReadOnlyList<string> MemberOf { get; init; } = Array.Empty<string>();
        public string? MailNickname { get; init; }
        public string? CanonicalName { get; init; }
        public string? AltRecipient { get; init; }
        public IReadOnlyList<string> ProxyAddresses { get; init; } = Array.Empty<string>();
        public string? TargetAddress { get; init; }
        public string? ProtocolSettings { get; init; }
        public string? AccountNameHistory { get; init; }
        public string? HomePostalAddress { get; init; }
        public string? ApplicationName { get; init; }
        public string? AssetNumber { get; init; }
        public string? Assistant { get; init; }
        public string? AttributeDisplayNames { get; init; }
        public DateTime? BadPasswordTime { get; init; }
        public string? BadPwdCount { get; init; }
        public string? BuildingName { get; init; }
        public string? BusinessCategory { get; init; }
        public string? CarLicense { get; init; }
        public string? ClassDisplayName { get; init; }
        public string? CreateTimeStamp { get; init; }
        public DateTime? CreationTime { get; init; }
        public string? DepartmentNumber { get; init; }
        public string? Division { get; init; }
        public string? DriverName { get; init; }
        public string? EmployeeID { get; init; }
        public string? EmployeeNumber { get; init; }
        public string? EmployeeType { get; init; }
        public string? ExtensionName { get; init; }
        public string? FriendlyNames { get; init; }
        public string? GlobalAddressList { get; init; }
        public string? Keywords { get; init; }
        public DateTime? LastBackupRestorationTime { get; init; }
        public DateTime? LastLogoff { get; init; }
        public DateTime? LastLogon { get; init; }
        public DateTime? LastLogonTimestamp { get; init; }
        public DateTime? LastSetTime { get; init; }
        public string? Location { get; init; }
        public DateTime? LockoutDuration { get; init; }
        public DateTime? LockoutTime { get; init; }
        public int LogonCount { get; init; }
        public string? ManagedBy { get; init; }
        public string? NCName { get; init; }
        public string? OperatingSystem { get; init; }
        public string? OperatingSystemServicePack { get; init; }
        public string? OperatingSystemVersion { get; init; }
        public string? OptionDescription { get; init; }
        public string? O { get; init; }
        public string? OtherMailbox { get; init; }
        public string? MiddleName { get; init; }
        public string? Owner { get; init; }
        public string? PersonalTitle { get; init; }
        public string? PostalAddress { get; init; }
        public string? Name { get; init; }
        public string? ServicePrincipalName { get; init; }
        public string? MailAddress { get; init; }
        public string? Street { get; init; }
        public string? UPNSuffixes { get; init; }
        public string? PrimaryGroupID { get; init; }
        public string? PrimaryGroupDescription { get; init; }
        public string? UserAccountControl { get; init; }
        public IReadOnlyList<string> UserAccountControlValues { get; init; } = Array.Empty<string>();
    }
}
