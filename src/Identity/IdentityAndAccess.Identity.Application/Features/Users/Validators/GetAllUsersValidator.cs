using FluentValidation;
using IdentityAndAccess.Identity.Application.Features.Users.Queries;

namespace IdentityAndAccess.Identity.Application.Features.Users.Validators
{
    public sealed class GetAllUsersValidator : AbstractValidator<GetAllUsersQuery>
    {
        public GetAllUsersValidator()
        {
            // O nome segue o parâmetro público da API (?ad=).
            RuleFor(x => x.Domain)
                .NotEmpty().WithMessage("O domínio (ad) não pode ser vazio.")
                .OverridePropertyName("ad");
        }
    }
}
