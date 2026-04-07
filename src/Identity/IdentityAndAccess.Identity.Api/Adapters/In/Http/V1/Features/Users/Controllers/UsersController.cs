using Asp.Versioning;
using Cqrsly;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Users.Mapping;
using IdentityAndAccess.Identity.Application.Features.Users.Queries;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Users.Controllers
{
#if RELEASE
    [Authorize(AuthenticationSchemes = "Basic")]
#endif

    [ApiVersion("1.0")]
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")]
    public sealed class UsersController : ControllerBase
    {
        private readonly ICqrsly _cqrsly;

        public UsersController(ICqrsly cqrsly) => _cqrsly = cqrsly;

        /// <summary>
        /// GET /api/v1/users?ad={adDomain}&samaccountname={samaccountname}
        /// Retorna todos os usuários de um dado domínio Active Directory ou um usuário específico.
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> GetAllUsers([FromQuery] string ad, [FromQuery] string? samaccountname, CancellationToken ct)
        {
            var query = new GetAllUsersQuery(ad, samaccountname);
            var result = await _cqrsly.Send(query, ct);

            return Ok(result.ToResponse());
        }
    }
}
