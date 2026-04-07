namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Users.Contracts.Responses
{
    public sealed class GetAllUsersResponse
    {
        public bool Success { get; init; }
        public object? Data { get; init; }
    }
}
