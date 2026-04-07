namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Contracts.Requests
{
    public sealed class ValidateCredentialsRequest
    {
        public string Username { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
        public string Ad { get; init; } = string.Empty; // AD domain
    }
}
