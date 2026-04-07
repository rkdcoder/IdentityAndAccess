using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Platform.Identity.Abstractions.Options;

namespace Platform.Identity.Abstractions.Extensions
{
    public static class ConfigurationExtensions
    {
        public static IServiceCollection AddDirectoryServicesOptions(this IServiceCollection services, IConfiguration cfg)
        {
            services.Configure<DirectoryServicesOptions>(cfg.GetSection("DirectoryServices"));
            return services;
        }
    }
}