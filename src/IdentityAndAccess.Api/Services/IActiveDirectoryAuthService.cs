using IdentityAndAccess.Api.Models;

namespace IdentityAndAccess.Api.Services;

public interface IActiveDirectoryAuthService
{
    /// <summary>
    /// Valida as credenciais e devolve os dados do usuário.
    /// </summary>
    /// <exception cref="Exceptions.DirectoryUnavailableException">Nenhum controlador de domínio respondeu.</exception>
    Task<(bool Success, string Message, AdUser? User)> ValidateAndGetAsync(
        string domain, string username, string password, CancellationToken ct);
}
