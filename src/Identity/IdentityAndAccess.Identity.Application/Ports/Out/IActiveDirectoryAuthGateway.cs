using IdentityAndAccess.Identity.Domain.Features.Auth.Entities;

namespace IdentityAndAccess.Identity.Application.Ports.Out
{
    public interface IActiveDirectoryAuthGateway
    {
        /// <summary>
        /// Validate credentials and returns user infos.
        /// </summary>
        Task<(bool Success, string Message, AdUser? User)> ValidateAndGetAsync(
            string domain, string username, string password, CancellationToken ct);
    }
}