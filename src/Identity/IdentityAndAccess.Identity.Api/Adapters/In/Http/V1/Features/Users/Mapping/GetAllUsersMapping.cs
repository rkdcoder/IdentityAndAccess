using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Users.Contracts.Responses;
using IdentityAndAccess.Identity.Application.Features.Users.Queries.Results;

namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Users.Mapping
{
    public static class GetAllUsersMapping
    {
        public static GetAllUsersResponse ToResponse(this GetAllUsersResult result)
            => new()
            {
                Success = result.Success,
                Data = result.Users
            };
    }
}
