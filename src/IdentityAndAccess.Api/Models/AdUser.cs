namespace IdentityAndAccess.Api.Models
{
    public sealed class AdUser
    {
        public string? DisplayName { get; init; }
        public string? UserPrincipalName { get; init; }
        public string? SamAccountName { get; init; }
        public string? DistinguishedName { get; init; }
        public string? Email { get; init; }
        public string? GivenName { get; init; }
        public string? Surname { get; init; }
        public string? MiddleName { get; init; }
        public string? Department { get; init; }
        public string? Company { get; init; }
        public string? Title { get; init; }
        public string? Manager { get; init; }
        public string? Office { get; init; }
        public string? StreetAddress { get; init; }
        public string? City { get; init; }
        public string? State { get; init; }
        public string? PostalCode { get; init; }
        public string? CountryCode { get; init; }
        public string? Telephone { get; init; }
        public string? Mobile { get; init; }
        public bool? Enabled { get; init; }
        public string? Sid { get; init; }
        public DateTime? AccountExpirationDate { get; init; }
        public DateTime? LastLogon { get; init; }
        public DateTime? WhenCreated { get; init; }
        public DateTime? WhenChanged { get; init; }
        public bool? PasswordNeverExpires { get; init; }
        public bool? PasswordNotRequired { get; init; }
        public DateTime? PasswordLastSet { get; init; }
        public IReadOnlyList<string> MemberOf { get; init; } = Array.Empty<string>();
    }
}