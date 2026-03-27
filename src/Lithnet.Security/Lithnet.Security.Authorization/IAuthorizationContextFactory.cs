using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Lithnet.Security.Authorization
{
    public interface IAuthorizationContextFactory
    {
        IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity);

        IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity, string server);

        IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity, string server, AuthzInitFlags flags);

        IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity, string server, bool allowLocalFallback, AuthzInitFlags flags);

        IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken);

        IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken, string server);

        IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken, string server, AuthzInitFlags flags);

        IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken, string server, bool allowLocalFallback, AuthzInitFlags flags);
    }
}