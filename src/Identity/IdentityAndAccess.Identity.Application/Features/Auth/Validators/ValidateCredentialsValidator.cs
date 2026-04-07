using FluentValidation;

namespace IdentityAndAccess.Identity.Application.Features.Auth.Validators
{
    public sealed class ValidateCredentialsValidator : AbstractValidator<(string domain, string username, string password)>
    {
        public ValidateCredentialsValidator()
        {
            RuleFor(x => x.domain).NotEmpty().MaximumLength(256);
            RuleFor(x => x.username).NotEmpty().MaximumLength(256);
            RuleFor(x => x.password).NotEmpty();
        }
    }
}