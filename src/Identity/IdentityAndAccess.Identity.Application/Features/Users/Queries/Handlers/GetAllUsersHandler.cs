using Cqrsly;
using FluentValidation;
using IdentityAndAccess.Identity.Application.Features.Users.Queries.Results;
using IdentityAndAccess.Identity.Application.Features.Users.Validators;
using IdentityAndAccess.Identity.Application.Ports.Out;

namespace IdentityAndAccess.Identity.Application.Features.Users.Queries.Handlers
{
    public sealed class GetAllUsersHandler : IRequestHandler<GetAllUsersQuery, GetAllUsersResult>
    {
        private static readonly GetAllUsersValidator Validator = new();

        private readonly IActiveDirectoryUsersGateway _adGateway;

        public GetAllUsersHandler(IActiveDirectoryUsersGateway adGateway) => _adGateway = adGateway;

        public async Task<GetAllUsersResult> Handle(GetAllUsersQuery request, CancellationToken ct)
        {
            // Lança FluentValidation.ValidationException (mapeada para 400 na API).
            await Validator.ValidateAndThrowAsync(request, ct);

            var users = await _adGateway.GetAllUsersAsync(request.Domain, request.SamAccountName, ct);
            return GetAllUsersResult.Ok(users);
        }
    }
}
