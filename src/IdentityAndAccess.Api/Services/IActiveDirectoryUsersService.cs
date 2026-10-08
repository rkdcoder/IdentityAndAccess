using IdentityAndAccess.Api.Models;

namespace IdentityAndAccess.Api.Services;

public interface IActiveDirectoryUsersService
{
    /// <exception cref="Exceptions.DirectoryUnavailableException">Nenhum controlador de domínio respondeu.</exception>
    Task<IReadOnlyList<AdUserDetails>> GetAllUsersAsync(string domain, string? samAccountName, CancellationToken ct);
}
