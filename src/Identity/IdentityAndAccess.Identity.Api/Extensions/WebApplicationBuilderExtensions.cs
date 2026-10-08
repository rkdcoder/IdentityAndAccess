using FluentValidation;
using IdentityAndAccess.Identity.Api.RateLimiting;
using IdentityAndAccess.Identity.Application.Exceptions;
using IdentityAndAccess.Identity.Application.Extensions;
using IdentityAndAccess.Identity.Infrastructure.Extensions;
using Microsoft.AspNetCore.Mvc;
using Rkd.Scalar;
using System.Threading.RateLimiting;

namespace IdentityAndAccess.Identity.Api.Extensions
{
    public static class WebApplicationBuilderExtensions
    {
        public static WebApplicationBuilder AddApiServices(this WebApplicationBuilder builder)
        {
            var services = builder.Services;

            services.AddControllers();
            services.AddAuthorization();
            services.AddEndpointsApiExplorer();

            // Rkd.Scalar: documentação (Scalar), versionamento, autenticação Basic, erros RFC 9457 e log HTTP.
            builder.AddRkdScalar()
                .WithVersioning("v1")
                // Mesma credencial ("Credentials": Username/Password) protege a UI do Scalar e a API.
                .WithUiProtection("Credentials")
                .WithBasicAuth("Credentials")
                .WithLowercaseRouting()
                .WithProblemDetails(ConfigureProblemDetails)
                // Opções lidas da seção "HttpLogging" (appsettings); o destino é o SQL Server.
                .WithHttpLogging()
                .WriteHttpLogsToSqlServer();

            AddRateLimiting(services, builder.Configuration);

            services.AddApplication();
            services.AddInfrastructure(builder.Configuration);

            return builder;
        }

        /// <summary>
        /// Limita por IP as tentativas de validação de credenciais (evita força bruta e bloqueio de contas no AD).
        /// Atrás de proxy/balanceador, o IP real depende de ForwardedHeaders (ASPNETCORE_FORWARDEDHEADERS_ENABLED=true).
        /// </summary>
        private static void AddRateLimiting(IServiceCollection services, IConfiguration configuration)
        {
            var limits = configuration.GetSection(AuthRateLimitOptions.SectionName).Get<AuthRateLimitOptions>()
                         ?? new AuthRateLimitOptions();

            services.AddRateLimiter(options =>
            {
                // Resposta sem corpo: o Rkd.Scalar a converte em problem details (429, TOO_MANY_REQUESTS).
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

                options.OnRejected = (context, _) =>
                {
                    if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                        context.HttpContext.Response.Headers.RetryAfter =
                            ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();

                    return ValueTask.CompletedTask;
                };

                options.AddPolicy(AuthRateLimitOptions.PolicyName, httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = Math.Max(1, limits.PermitLimit),
                            Window = TimeSpan.FromSeconds(Math.Max(1, limits.WindowSeconds)),
                            QueueLimit = 0
                        }));
            });
        }

        private static void ConfigureProblemDetails(RkdProblemDetailsOptions options)
        {
            options.UnexpectedError(
                code: "ERRO_INESPERADO",
                detail: "Ocorreu um erro inesperado. Informe o traceId ao suporte.",
                title: "Erro inesperado");

            // FluentValidation (handlers da Application) -> 400 com "errors" por campo.
            options.Map<ValidationException>(ex => RkdError.Validation(
                    ex.Errors
                        .GroupBy(e => e.PropertyName)
                        .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).ToArray()))
                .ToProblemDetails());

            // Nenhum controlador de domínio do AD respondeu.
            options.Map<DirectoryUnavailableException>(ex => new ProblemDetails
            {
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Active Directory indisponível",
                Detail = ex.Message,
                Extensions = { ["code"] = "DIRECTORY_UNAVAILABLE" }
            });
        }
    }
}
