using HttpGossip;
using IdentityAndAccess.Identity.Api.Security;
using IdentityAndAccess.Identity.Application.Extensions;
using IdentityAndAccess.Identity.Infrastructure.Extensions;
using Rkd.ApiException.Extensions;
using Rkd.Scalar.Extensions;
using Rkd.Scalar.Security.Jwt;
using System.Configuration;


namespace IdentityAndAccess.Identity.Api.Extensions
{
    public static class WebApplicationBuilderExtensions
    {
        public static WebApplicationBuilder AddApiServices(this WebApplicationBuilder builder)
        {
            var services = builder.Services;
            var cfg = builder.Configuration;

            services.AddControllers();
            services.AddAuthorization();

            // Scalar and versioning
            services
                .AddRkdScalar(builder.Configuration)
                .WithVersioning("v1")
                .WithUiProtection<CredentialsValidator>()
                .WithBasicAuth<CredentialsValidator>()
                .WithLowercaseRouting();

            // Cqrs, Infra and exception middleware Middleware
            services.AddApplication();
            services.AddInfrastructure(builder.Configuration);

            services.AddRkdApiException(opts =>
            {
                opts.IncludeExceptionDetails = builder.Environment.IsDevelopment();
                // logging txt
            });

            // http request logging
            var section = cfg.GetSection("HttpGossip");
            services.AddHttpGossip(section.Bind);

            services.AddEndpointsApiExplorer();

            return builder;
        }
    }
}