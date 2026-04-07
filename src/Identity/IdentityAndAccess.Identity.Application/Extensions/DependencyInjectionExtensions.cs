using Cqrsly;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAndAccess.Identity.Application.Extensions
{
    public static class DependencyInjectionExtensions
    {
        public static IServiceCollection AddApplication(this IServiceCollection services)
        {
            services.AddCqrsly(cfg => cfg
                .AddHandlersFromAssemblyContaining<ApplicationAssemblyMarker>()); 
            return services;
        }
    }
}