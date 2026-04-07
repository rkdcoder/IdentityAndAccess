using IdentityAndAccess.Identity.Domain.Features.Auth.Entities;

namespace IdentityAndAccess.Identity.Application.Features.Users.Queries.Results
{
    public sealed class GetAllUsersResult
    {
        public bool Success { get; init; }
        public IReadOnlyList<AdUserDetails>? Users { get; init; }

        public static GetAllUsersResult Ok(IReadOnlyList<AdUserDetails> users)
            => new() { Success = true, Users = users };
    }
}
