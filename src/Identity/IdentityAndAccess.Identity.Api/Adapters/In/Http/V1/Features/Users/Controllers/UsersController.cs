using Asp.Versioning;
using Cqrsly;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Users.Mapping;
using IdentityAndAccess.Identity.Application.Features.Users.Queries;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Rkd.Scalar;

namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Users.Controllers
{
    [Authorize(AuthenticationSchemes = RkdScalarAuthenticationSchemes.Basic)]
    [ApiVersion("1.0")]
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")]
    public sealed class UsersController : ControllerBase
    {
        private readonly ICqrsly _cqrsly;

        public UsersController(ICqrsly cqrsly) => _cqrsly = cqrsly;

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
        public async Task<IActionResult> GetAllUsers([FromQuery] string ad, [FromQuery] string? samaccountname, CancellationToken ct)
        {
            var query = new GetAllUsersQuery(ad, samaccountname);
            var result = await _cqrsly.Send(query, ct);

            return Ok(result.ToResponse());
        }
    }
}
