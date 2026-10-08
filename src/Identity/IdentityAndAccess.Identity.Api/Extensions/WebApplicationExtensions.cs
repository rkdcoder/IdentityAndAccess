using Scalar.AspNetCore;

namespace IdentityAndAccess.Identity.Api.Extensions
{
    public static class WebApplicationExtensions
    {
        public static WebApplication UseApi(this WebApplication app)
        {
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

            return app;
        }
    }
}
