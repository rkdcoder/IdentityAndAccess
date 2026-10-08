namespace IdentityAndAccess.Api.Models;

public sealed class GetAllUsersResponse
{
    public bool Success { get; init; }
    public IReadOnlyList<AdUserDetails> Data { get; init; } = Array.Empty<AdUserDetails>();
}
