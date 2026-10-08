namespace IdentityAndAccess.Api.Models;

public sealed class ValidateCredentialsResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public AdUser? UserInfos { get; init; }
}
