using Asp.Versioning;
using IdentityAndAccess.Api.Models;
using IdentityAndAccess.Api.Options;
using IdentityAndAccess.Api.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Rkd.Scalar;

namespace IdentityAndAccess.Api.Controllers;

[ApiVersion("1.0")]
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
public sealed class AuthController(IActiveDirectoryAuthService activeDirectory) : ControllerBase
{
    /// <summary>
    /// Valida as credenciais de um usuário no Active Directory.
    /// </summary>
    /// <remarks>
    /// Em caso de sucesso retorna os dados do usuário. O corpo (que contém a senha) nunca é gravado no log HTTP.
    /// </remarks>
    /// <response code="200">Credenciais válidas.</response>
    /// <response code="401">Credenciais inválidas, senha expirada ou usuário inexistente.</response>
    /// <response code="429">Limite de tentativas por IP excedido (veja o header Retry-After).</response>
    /// <response code="503">Active Directory indisponível.</response>
    [HttpPost("validate")]
    [SensitiveHttpLog]
    [EnableRateLimiting(AuthRateLimitOptions.PolicyName)]
    [ProducesResponseType<ValidateCredentialsResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ValidateCredentialsResponse>(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Validate([FromBody] ValidateCredentialsRequest req, CancellationToken ct)
    {
        var (success, message, user) = await activeDirectory.ValidateAndGetAsync(req.Ad, req.Username, req.Password, ct);

        if (!success || user is null)
            return Unauthorized(new ValidateCredentialsResponse { Success = false, Message = message });

        return Ok(new ValidateCredentialsResponse
        {
            Success = true,
            Message = "Credenciais validadas com sucesso.",
            UserInfos = user
        });
    }
}
