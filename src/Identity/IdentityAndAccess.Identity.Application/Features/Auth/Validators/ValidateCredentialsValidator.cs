using FluentValidation;
using IdentityAndAccess.Identity.Application.Features.Auth.Commands;

namespace IdentityAndAccess.Identity.Application.Features.Auth.Validators
{
    public sealed class ValidateCredentialsValidator : AbstractValidator<ValidateCredentialsCommand>
    {
        public ValidateCredentialsValidator()
        {
            // Os nomes seguem o contrato público da API (ValidateCredentialsRequest).
            RuleFor(x => x.Domain)
                .NotEmpty().WithMessage("O domínio (ad) não pode ser vazio.")
                .MaximumLength(256).WithMessage("O domínio (ad) deve ter no máximo 256 caracteres.")
                .OverridePropertyName("ad");

            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("O usuário não pode ser vazio.")
                .MaximumLength(256).WithMessage("O usuário deve ter no máximo 256 caracteres.")
                .OverridePropertyName("username");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("A senha não pode ser vazia.")
                .OverridePropertyName("password");
        }
    }
}
