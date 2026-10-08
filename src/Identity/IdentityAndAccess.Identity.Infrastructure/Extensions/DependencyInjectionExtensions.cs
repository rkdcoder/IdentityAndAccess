using IdentityAndAccess.Identity.Application.Ports.Out;
using IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory;
using IdentityAndAccess.Identity.Infrastructure.Adapters.Out.ExternalClients.ActiveDirectory.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Platform.Identity.Abstractions.Extensions;

namespace IdentityAndAccess.Identity.Infrastructure.Extensions
{
    public static class DependencyInjectionExtensions
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration cfg)
        {
            services.AddDirectoryServicesOptions(cfg);

            // Mantêm cache de controladores de domínio e política de senha: precisam ser singletons.
            services.AddSingleton<DomainControllerResolver>();
            services.AddSingleton<PasswordPolicyReader>();

            services.AddScoped<IActiveDirectoryAuthGateway, ActiveDirectoryAuthGateway>();
            services.AddScoped<IActiveDirectoryUsersGateway, ActiveDirectoryUsersGateway>();
            return services;
        }
    }
}
