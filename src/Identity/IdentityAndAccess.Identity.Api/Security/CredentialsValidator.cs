using Rkd.Scalar.Security.Basic;
using Rkd.Scalar.Security.Contracts;
using System.Security.Claims;

namespace IdentityAndAccess.Identity.Api.Security
{
    public class CredentialsValidator : ICredentialValidator<BasicAuthCredentials>
    {
        private readonly IConfiguration _configuration;

        public CredentialsValidator(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public Task<ClaimsIdentity?> ValidateAsync(
            BasicAuthCredentials request,
            CancellationToken cancellationToken = default)
        {
            var configUsername = _configuration["Credentials:Username"];
            var configPassword = _configuration["Credentials:Password"];

            if (string.IsNullOrEmpty(configUsername) || string.IsNullOrEmpty(configPassword))
            {
                return Task.FromResult<ClaimsIdentity?>(null);
            }

            bool isUsernameValid = string.Equals(request.Username, configUsername, StringComparison.InvariantCultureIgnoreCase);

            bool isPasswordValid = request.Password == configPassword;

            if (isUsernameValid && isPasswordValid)
            {
                var identity = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(ClaimTypes.Name, configUsername),
                        new Claim(ClaimTypes.Role, "ADMIN")
                    },
                    "Basic"
                );

                return Task.FromResult<ClaimsIdentity?>(identity);
            }

            return Task.FromResult<ClaimsIdentity?>(null);
        }
    }
}
