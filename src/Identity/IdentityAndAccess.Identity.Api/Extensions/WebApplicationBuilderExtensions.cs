using FluentValidation;
using IdentityAndAccess.Identity.Application.Exceptions;
using IdentityAndAccess.Identity.Application.Extensions;
using IdentityAndAccess.Identity.Infrastructure.Extensions;
using Microsoft.AspNetCore.Mvc;
using Rkd.Scalar;

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

            services.AddApplication();
            services.AddInfrastructure(builder.Configuration);

            return builder;
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
