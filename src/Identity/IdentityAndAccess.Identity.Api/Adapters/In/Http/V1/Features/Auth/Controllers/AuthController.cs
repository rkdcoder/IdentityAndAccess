using Asp.Versioning;
using Cqrsly;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Contracts.Requests;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Contracts.Responses;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Mapping;
using IdentityAndAccess.Identity.Application.Features.Auth.Commands;
using Microsoft.AspNetCore.Mvc;
using Rkd.Scalar;

namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Controllers
{
    [ApiVersion("1.0")]
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")]
    public sealed class AuthController : ControllerBase
    {
        private readonly ICqrsly _cqrsly;
        public AuthController(ICqrsly cqrsly) => _cqrsly = cqrsly;

        /// <summary>
        /// Valida as credenciais de um usuário no Active Directory.
        /// </summary>
        /// <remarks>
        /// Em caso de sucesso retorna os dados do usuário. O corpo (que contém a senha) nunca é gravado no log HTTP.
        /// </remarks>
        /// <response code="200">Credenciais válidas.</response>
        /// <response code="401">Credenciais inválidas, senha expirada ou usuário inexistente.</response>
        /// <response code="503">Active Directory indisponível.</response>
        [HttpPost("validate")]
        [SensitiveHttpLog]
        [ProducesResponseType<ValidateCredentialsResponse>(StatusCodes.Status200OK)]
        [ProducesResponseType<ValidateCredentialsResponse>(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Validate([FromBody] ValidateCredentialsRequest req, CancellationToken ct)
        {
            var cmd = new ValidateCredentialsCommand(req.Ad, req.Username, req.Password);

            var result = await _cqrsly.Send(cmd, ct);

            var response = result.ToResponse();

            return result.Success ? Ok(response) : Unauthorized(response);
        }
    }
}
