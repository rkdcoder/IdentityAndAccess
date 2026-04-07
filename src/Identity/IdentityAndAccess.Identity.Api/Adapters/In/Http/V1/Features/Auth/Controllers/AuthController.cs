using Asp.Versioning;
using Cqrsly;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Contracts.Requests;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Contracts.Responses;
using IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Mapping;
using IdentityAndAccess.Identity.Application.Features.Auth.Commands;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace IdentityAndAccess.Identity.Api.Adapters.In.Http.V1.Features.Auth.Controllers
{
    [ApiVersion("1.0")]
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")]
    public sealed class AuthController : ControllerBase
    {
        private readonly ICqrsly _cqrsly;
        public AuthController(ICqrsly cqrsly) => _cqrsly = cqrsly;

        [HttpPost("validate")]
        public async Task<IActionResult> Validate([FromBody] ValidateCredentialsRequest req, CancellationToken ct)
        {

            var cmd = new ValidateCredentialsCommand(req.Ad, req.Username, req.Password);

            var result = await _cqrsly.Send(cmd, ct);

            if (!result.Success)
            {

                return Unauthorized(result.ToResponse());
            }

            ValidateCredentialsResponse resp = result.ToResponse();
            return Ok(resp);
        }
    }
}