using Asp.Versioning;
using IdentityAndAccess.Api.Models;
using IdentityAndAccess.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Rkd.Scalar;
using System.ComponentModel.DataAnnotations;

namespace IdentityAndAccess.Api.Controllers;

[Authorize(AuthenticationSchemes = RkdScalarAuthenticationSchemes.Basic)]
[ApiVersion("1.0")]
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
public sealed class UsersController(IActiveDirectoryUsersService activeDirectory) : ControllerBase
{
    /// <summary>
    /// Retorna todos os usuários de um domínio Active Directory ou um usuário específico.
    /// </summary>
    /// <param name="ad">Domínio (ou IP do controlador de domínio) do Active Directory.</param>
    /// <param name="samaccountname">Filtra por um sAMAccountName específico (opcional).</param>
    /// <param name="ct">Token de cancelamento.</param>
    /// <remarks>
    /// Requer autenticação Basic. O corpo da resposta (dados pessoais) não é gravado no log HTTP.
    /// </remarks>
    [HttpGet]
    [SensitiveHttpLog]
    public async Task<ActionResult<GetAllUsersResponse>> GetAllUsers(
        [FromQuery, Required(ErrorMessage = "O domínio (ad) não pode ser vazio.")] string ad,
        [FromQuery] string? samaccountname,
        CancellationToken ct)
    {
        var users = await activeDirectory.GetAllUsersAsync(ad, samaccountname, ct);

        return Ok(new GetAllUsersResponse { Success = true, Data = users });
    }
}
