using IdentityAndAccess.Api.Exceptions;
using IdentityAndAccess.Api.Models;
using IdentityAndAccess.Api.Options;
using IdentityAndAccess.Api.Services.ActiveDirectory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Net;

namespace IdentityAndAccess.Api.Services;

public sealed class ActiveDirectoryAuthService : IActiveDirectoryAuthService
{
    private const int UacPasswordNotRequired = 0x0020;
    private const int UacPasswordNeverExpires = 0x10000;

    private readonly DirectoryServicesOptions _opts;
    private readonly DomainControllerResolver _resolver;
    private readonly PasswordPolicyReader _passwordPolicy;
    private readonly ILogger<ActiveDirectoryAuthService> _logger;

    public ActiveDirectoryAuthService(
        IOptions<DirectoryServicesOptions> opts,
        DomainControllerResolver resolver,
        PasswordPolicyReader passwordPolicy,
        ILogger<ActiveDirectoryAuthService> logger)
    {
        _opts = opts.Value;
        _resolver = resolver;
        _passwordPolicy = passwordPolicy;
        _logger = logger;
    }

    public async Task<(bool Success, string Message, AdUser? User)> ValidateAndGetAsync(
        string domain,
        string username,
        string password,
        CancellationToken ct)
    {
        var ctxOptions = ParseContextOptions(_opts.ContextOptions);

        var domainControllers = await _resolver.ResolveAsync(domain, ct);
        var maxPwdAge = await _passwordPolicy.GetMaxPasswordAgeAsync(domain, ct);

        Exception? lastError = null;

        foreach (var dc in domainControllers)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                // As APIs de System.DirectoryServices são síncronas: não bloqueia a thread da requisição.
                return await Task.Run(
                    () => ValidateOnDomainController(dc, domain, username, password, ctxOptions, maxPwdAge),
                    ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Falha ao validar credenciais no controlador de domínio {DomainController} ({Domain}).", dc, domain);
                lastError = ex;
            }
        }

        throw new DirectoryUnavailableException(domain, lastError);
    }

    private static (bool Success, string Message, AdUser? User) ValidateOnDomainController(
        string dc,
        string domain,
        string username,
        string password,
        ContextOptions ctxOptions,
        TimeSpan maxPwdAge)
    {
        using var context = new PrincipalContext(ContextType.Domain, dc, null, ctxOptions);

        using var user = UserPrincipal.FindByIdentity(context, username);

        if (user is null)
            return (false, "Usuário não encontrado no domínio informado.", null);

        var ok = context.ValidateCredentials(username, password, ctxOptions);

        var entry = (DirectoryEntry?)user.GetUnderlyingObject();

        var pwdLastSet = DirectoryEntryReader.GetFileTime(entry, "pwdLastSet");
        var uac = DirectoryEntryReader.GetInt(entry, "userAccountControl");

        bool neverExpires = (uac & UacPasswordNeverExpires) != 0;
        bool mustChange = pwdLastSet == null || pwdLastSet.Value == DateTime.MinValue;

        bool isExpired = false;

        if (!neverExpires && pwdLastSet.HasValue && maxPwdAge > TimeSpan.Zero)
            isExpired = pwdLastSet.Value.Add(maxPwdAge) <= DateTime.UtcNow;

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
                return (false, "Acesso negado: credenciais pertencem a outro domínio.", null);
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
            MiddleName = DirectoryEntryReader.GetString(entry, "middleName"),
            Department = DirectoryEntryReader.GetString(entry, "department"),
            Company = DirectoryEntryReader.GetString(entry, "company"),
            Title = DirectoryEntryReader.GetString(entry, "title"),
            Manager = DirectoryEntryReader.GetString(entry, "manager"),
            Office = DirectoryEntryReader.GetString(entry, "physicalDeliveryOfficeName"),
            StreetAddress = DirectoryEntryReader.GetString(entry, "streetAddress"),
            City = DirectoryEntryReader.GetString(entry, "l"),
            State = DirectoryEntryReader.GetString(entry, "st"),
            PostalCode = DirectoryEntryReader.GetString(entry, "postalCode"),
            CountryCode = DirectoryEntryReader.GetString(entry, "countryCode"),
            Telephone = user.VoiceTelephoneNumber ?? DirectoryEntryReader.GetString(entry, "telephoneNumber"),
            Mobile = DirectoryEntryReader.GetString(entry, "mobile"),
            Enabled = user.Enabled,
            Sid = user.Sid?.Value,
            AccountExpirationDate = user.AccountExpirationDate,
            LastLogon = DirectoryEntryReader.GetFileTime(entry, "lastLogonTimestamp"),
            WhenCreated = DirectoryEntryReader.GetDate(entry, "whenCreated"),
            WhenChanged = DirectoryEntryReader.GetDate(entry, "whenChanged"),
            PasswordNeverExpires = neverExpires,
            PasswordNotRequired = (uac & UacPasswordNotRequired) != 0,
            PasswordLastSet = pwdLastSet,
            MemberOf = DirectoryEntryReader.GetMulti(entry, "memberOf")
        };

        return (true, "Credenciais válidas.", adUser);
    }

    private static ContextOptions ParseContextOptions(string input)
        => Enum.TryParse<ContextOptions>(input, true, out var result)
           ? result
           : ContextOptions.Negotiate;
}
