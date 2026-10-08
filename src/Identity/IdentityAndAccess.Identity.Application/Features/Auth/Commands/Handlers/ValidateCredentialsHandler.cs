using Cqrsly;
using FluentValidation;
using IdentityAndAccess.Identity.Application.Features.Auth.Commands.Results;
using IdentityAndAccess.Identity.Application.Features.Auth.Validators;
using IdentityAndAccess.Identity.Application.Ports.Out;

namespace IdentityAndAccess.Identity.Application.Features.Auth.Commands.Handlers
{
    public sealed class ValidateCredentialsHandler
        : IRequestHandler<ValidateCredentialsCommand, ValidateCredentialsResult>
    {
        private static readonly ValidateCredentialsValidator Validator = new();

        private readonly IActiveDirectoryAuthGateway _ad;

        public ValidateCredentialsHandler(IActiveDirectoryAuthGateway ad) => _ad = ad;

        public async Task<ValidateCredentialsResult> Handle(ValidateCredentialsCommand request, CancellationToken ct)
        {
            // Lança FluentValidation.ValidationException (mapeada para 400 na API).
            await Validator.ValidateAndThrowAsync(request, ct);

            // Lança DirectoryUnavailableException (mapeada para 503) se nenhum controlador de domínio responder.
            var (success, message, user) = await _ad.ValidateAndGetAsync(
                request.Domain, request.Username, request.Password, ct);

            if (!success || user is null)
                return ValidateCredentialsResult.Fail(message);

            var payload = new
            {
                user.DisplayName,
                user.UserPrincipalName,
                user.SamAccountName,
                user.DistinguishedName,
                user.Email,
                user.GivenName,
                user.Surname,
                user.MiddleName,
                user.Department,
                user.Company,
                user.Title,
                user.Manager,
                user.Office,
                user.StreetAddress,
                user.City,
                user.State,
                user.PostalCode,
                user.CountryCode,
                user.Telephone,
                user.Mobile,
                user.Enabled,
                user.Sid,
                user.AccountExpirationDate,
                user.LastLogon,
                user.WhenCreated,
                user.WhenChanged,
                user.PasswordNeverExpires,
                user.PasswordNotRequired,
                user.PasswordLastSet,
                user.MemberOf
            };

            return ValidateCredentialsResult.Ok("Credenciais validadas com sucesso.", payload);
        }
    }
}
