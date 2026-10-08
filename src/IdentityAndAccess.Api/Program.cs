using IdentityAndAccess.Api.Exceptions;
using IdentityAndAccess.Api.Options;
using IdentityAndAccess.Api.Services;
using IdentityAndAccess.Api.Services.ActiveDirectory;
using Microsoft.AspNetCore.Mvc;
using Rkd.Scalar;
using Scalar.AspNetCore;
using System.Text.Json;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.AddControllers();
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();

// Rkd.Scalar: documentação (Scalar), versionamento, autenticação Basic, erros RFC 9457 e log HTTP.
builder.AddRkdScalar()
    .WithVersioning("v1")
    // A mesma credencial (seção "Credentials": Username/Password) protege a UI do Scalar e a API.
    .WithUiProtection("Credentials")
    .WithBasicAuth("Credentials")
    .WithLowercaseRouting()
    // Mesmo nome de campo nas respostas e nos erros de validação ("ad", "username", "password").
    .WithJsonNaming(JsonNamingPolicy.CamelCase)
    .WithProblemDetails(options =>
    {
        options.UnexpectedError(
            code: "ERRO_INESPERADO",
            detail: "Ocorreu um erro inesperado. Informe o traceId ao suporte.",
            title: "Erro inesperado");

        // Nenhum controlador de domínio do AD respondeu.
        options.Map<DirectoryUnavailableException>(ex => new ProblemDetails
        {
            Status = StatusCodes.Status503ServiceUnavailable,
            Title = "Active Directory indisponível",
            Detail = ex.Message,
            Extensions = { ["code"] = "DIRECTORY_UNAVAILABLE" }
        });
    })
    // Opções lidas da seção "HttpLogging" (appsettings); o destino é o SQL Server.
    .WithHttpLogging()
    .WriteHttpLogsToSqlServer();

// Limita por IP as tentativas de validação de credenciais (evita força bruta e bloqueio de contas no AD).
// Atrás de proxy/balanceador, o IP real depende de ASPNETCORE_FORWARDEDHEADERS_ENABLED=true.
var authLimit = configuration.GetSection(AuthRateLimitOptions.SectionName).Get<AuthRateLimitOptions>()
                ?? new AuthRateLimitOptions();

builder.Services.AddRateLimiter(options =>
{
    // Resposta sem corpo: o Rkd.Scalar a converte em problem details (429, TOO_MANY_REQUESTS).
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.OnRejected = (context, _) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();

        return ValueTask.CompletedTask;
    };

    options.AddPolicy(AuthRateLimitOptions.PolicyName, httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, authLimit.PermitLimit),
                Window = TimeSpan.FromSeconds(Math.Max(1, authLimit.WindowSeconds)),
                QueueLimit = 0
            }));
});

// Active Directory. Resolver e leitor de política mantêm cache: precisam ser singletons.
builder.Services.Configure<DirectoryServicesOptions>(configuration.GetSection("DirectoryServices"));
builder.Services.AddSingleton<DomainControllerResolver>();
builder.Services.AddSingleton<PasswordPolicyReader>();
builder.Services.AddScoped<IActiveDirectoryAuthService, ActiveDirectoryAuthService>();
builder.Services.AddScoped<IActiveDirectoryUsersService, ActiveDirectoryUsersService>();

var app = builder.Build();

// Erros (problem details) e log HTTP são adicionados no início do pipeline pelo Rkd.Scalar.
app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.UseRkdScalar(options =>
{
    options.Title = "Identity and Access Api";
    options.DarkMode = true;
    options.ConfigureScalar = scalar => scalar.Theme = ScalarTheme.BluePlanet;
});

app.Run();
