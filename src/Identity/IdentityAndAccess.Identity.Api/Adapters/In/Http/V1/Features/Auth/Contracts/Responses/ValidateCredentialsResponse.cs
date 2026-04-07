namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Contracts.Responses
{
    public sealed class ValidateCredentialsResponse
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public object? UserInfos { get; init; }
    }
}