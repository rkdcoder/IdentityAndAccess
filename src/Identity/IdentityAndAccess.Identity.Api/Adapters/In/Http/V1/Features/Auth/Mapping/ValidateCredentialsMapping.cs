using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Contracts.Responses;
using IdentityAndAccess.Identity.Application.Features.Auth.Commands.Results;

namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Mapping
{
    public static class ValidateCredentialsMapping
    {
        public static ValidateCredentialsResponse ToResponse(this ValidateCredentialsResult result)
            => new()
            {
                Success = result.Success,
                Message = result.Message,
                UserInfos = result.UserInfos
            };
    }
}