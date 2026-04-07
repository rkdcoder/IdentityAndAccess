using Cqrsly;
using IdentityAndAccess.Identity.Application.Features.Auth.Commands.Results;

namespace IdentityAndAccess.Identity.Application.Features.Auth.Commands
{
    public sealed class ValidateCredentialsCommand : IRequest<ValidateCredentialsResult>
    {
        public string Domain { get; }
        public string Username { get; }
        public string Password { get; }

        public ValidateCredentialsCommand(string domain, string username, string password)
        {
            Domain = domain;
            Username = username;
            Password = password;
        }
    }
}