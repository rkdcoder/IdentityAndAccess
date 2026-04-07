using Cqrsly;
using IdentityAndAccess.Identity.Application.Features.Users.Queries.Results;

namespace IdentityAndAccess.Identity.Application.Features.Users.Queries
{
    public sealed class GetAllUsersQuery : IRequest<GetAllUsersResult>
    {
        public string Domain { get; }
        public string? SamAccountName { get; }

        public GetAllUsersQuery(string domain, string? samAccountName = null)
        {
            Domain = domain;
            SamAccountName = samAccountName;
        }
    }
}
