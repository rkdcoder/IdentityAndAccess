using Cqrsly;
using IdentityAndAccess.Identity.Application.Features.Users.Queries.Results;
using IdentityAndAccess.Identity.Application.Features.Users.Validators;
using IdentityAndAccess.Identity.Application.Ports.Out;
using Rkd.ApiException.Abstractions;

namespace IdentityAndAccess.Identity.Application.Features.Users.Queries.Handlers
{
    public sealed class GetAllUsersHandler : IRequestHandler<GetAllUsersQuery, GetAllUsersResult>
    {
        private readonly IActiveDirectoryUsersGateway _adGateway;
        private readonly GetAllUsersValidator _validator;

        public GetAllUsersHandler(IActiveDirectoryUsersGateway adGateway)
        {
            _adGateway = adGateway;
            _validator = new GetAllUsersValidator();
        }

        public async Task<GetAllUsersResult> Handle(GetAllUsersQuery request, CancellationToken ct)
        {
            var valResult = await _validator.ValidateAsync(request, ct);
            if (!valResult.IsValid)
            {
                var allErrors = string.Join("; ", valResult.Errors.Select(e => $"{e.PropertyName}: {e.ErrorMessage}"));
                throw new RkdValidationException(allErrors);
            }

            var users = await _adGateway.GetAllUsersAsync(request.Domain, request.SamAccountName, ct);
            return GetAllUsersResult.Ok(users);
        }
    }
}
