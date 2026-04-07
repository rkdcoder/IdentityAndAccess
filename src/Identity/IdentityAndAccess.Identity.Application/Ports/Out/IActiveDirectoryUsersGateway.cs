using IdentityAndAccess.Identity.Domain.Features.Auth.Entities;

namespace IdentityAndAccess.Identity.Application.Ports.Out
{
    public interface IActiveDirectoryUsersGateway
    {
        Task<IReadOnlyList<AdUserDetails>> GetAllUsersAsync(string domain, string? samAccountName, CancellationToken ct);
    }
}
