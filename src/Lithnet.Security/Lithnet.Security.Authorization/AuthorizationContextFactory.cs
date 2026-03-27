using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Lithnet.Security.Authorization
{
    public class AuthorizationContextFactory : IAuthorizationContextFactory
    {
        public IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity)
        {
            return new AuthorizationContext(identity);
        }

        public IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity, string server)
        {
            return new AuthorizationContext(identity, server);
        }

        public IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity, string server, AuthzInitFlags flags)
        {
            return new AuthorizationContext(identity, server, flags);
        }

        public IAuthorizationContext CreateAuthorizationContext(SecurityIdentifier identity, string server, bool allowLocalFallback, AuthzInitFlags flags)
        {
            return new AuthorizationContext(identity, server, allowLocalFallback, flags);
        }

        public IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken)
        {
            return new AuthorizationContext(accessToken);
        }

        public IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken, string server)
        {
            return new AuthorizationContext(accessToken, server);
        }

        public IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken, string server, AuthzInitFlags flags)
        {
            return new AuthorizationContext(accessToken, server, flags);
        }

        public IAuthorizationContext CreateAuthorizationContext(SafeAccessTokenHandle accessToken, string server, bool allowLocalFallback, AuthzInitFlags flags)
        {
            return new AuthorizationContext(accessToken, server, allowLocalFallback, flags);
        }
    }
}