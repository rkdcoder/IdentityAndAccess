using FluentValidation;
using IdentityAndAccess.Identity.Application.Features.Users.Queries;

namespace IdentityAndAccess.Identity.Application.Features.Users.Validators
{
    public sealed class GetAllUsersValidator : AbstractValidator<GetAllUsersQuery>
    {
        public GetAllUsersValidator()
        {
            RuleFor(x => x.Domain).NotEmpty().WithMessage("O domínio não pode ser vazio.");
        }
    }
}
