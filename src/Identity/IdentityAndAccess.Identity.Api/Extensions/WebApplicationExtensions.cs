using HttpGossip;
using Rkd.ApiException.Extensions;
using Rkd.Scalar.Configuration;
using Rkd.Scalar.Extensions;
using Scalar.AspNetCore;

namespace IdentityAndAccess.Identity.Api.Extensions
{
    public static class WebApplicationExtensions
    {
        public static WebApplication UseApi(this WebApplication app)
        {
            app.UseRkdApiException();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseHttpGossip();

            app.MapControllers();

            app.UseRkdScalar(new RkdScalarConfiguration
            {
                Title = "Identity and Access Api",
                ConfigureScalar = opt =>
                {
                    opt.DarkMode = true;
                    opt.Theme = ScalarTheme.BluePlanet;
                }
            });

            return app;
        }
    }
}