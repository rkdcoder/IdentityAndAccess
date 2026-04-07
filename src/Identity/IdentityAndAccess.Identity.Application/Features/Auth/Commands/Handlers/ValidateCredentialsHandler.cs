using Cqrsly;
using FluentValidation;
using IdentityAndAccess.Identity.Application.Features.Auth.Commands.Results;
using IdentityAndAccess.Identity.Application.Features.Auth.Validators;
using IdentityAndAccess.Identity.Application.Ports.Out;
using Rkd.ApiException.Abstractions;

namespace IdentityAndAccess.Identity.Application.Features.Auth.Commands.Handlers
{
    public sealed class ValidateCredentialsHandler
        : IRequestHandler<ValidateCredentialsCommand, ValidateCredentialsResult>
    {
        private readonly IActiveDirectoryAuthGateway _ad;
        private readonly IValidator<(string domain, string username, string password)> _validator;

        public ValidateCredentialsHandler(IActiveDirectoryAuthGateway ad)
        {
            _ad = ad;
            _validator = new ValidateCredentialsValidator();
        }

        public async Task<ValidateCredentialsResult> Handle(ValidateCredentialsCommand request, CancellationToken ct)
        {
            var tuple = (request.Domain, request.Username, request.Password);
            var res = await _validator.ValidateAsync(tuple, ct);
            if (!res.IsValid)
            {
                var allErrors = string.Join("; ", res.Errors.Select(e => $"{e.PropertyName}: {e.ErrorMessage}"));
                throw new RkdValidationException(allErrors);
            }

            try
            {
                var (success, message, user) = await _ad.ValidateAndGetAsync(
                    request.Domain, request.Username, request.Password, ct);

                if (!success)
                {
                    return ValidateCredentialsResult.Fail(message);
                }

                // "userInfos" 
                var payload = new
                {
                    user?.DisplayName,
                    user?.UserPrincipalName,
                    user?.SamAccountName,
                    user?.DistinguishedName,
                    user?.Email,
                    user?.GivenName,
                    user?.Surname,
                    user?.MiddleName,
                    user?.Department,
                    user?.Company,
                    user?.Title,
                    user?.Manager,
                    user?.Office,
                    user?.StreetAddress,
                    user?.City,
                    user?.State,
                    user?.PostalCode,
                    user?.CountryCode,
                    user?.Telephone,
                    user?.Mobile,
                    user?.Enabled,
                    user?.Sid,
                    user?.AccountExpirationDate,
                    user?.LastLogon,
                    user?.WhenCreated,
                    user?.WhenChanged,
                    user?.PasswordNeverExpires,
                    user?.PasswordNotRequired,
                    user?.PasswordLastSet,
                    user?.MemberOf
                };

                return ValidateCredentialsResult.Ok("Credenciais validadas com sucesso.", payload);
            }
            catch (System.DirectoryServices.AccountManagement.PrincipalServerDownException)
            {
                // 404 + log
                throw new RkdNotFoundException("Não foi possível alcançar o active directory informado.");
            }
        }
    }
}