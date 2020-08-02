using System;
using System.Runtime.Serialization;

namespace Lithnet.Security.Authorization
{
    [Serializable]
    public class AuthorizationContextException : Exception
    {
        public AuthorizationContextException()
        {
        }

        public AuthorizationContextException(string message) : base(message)
        {
        }

        public AuthorizationContextException(string message, Exception inner) : base(message, inner)

        {
        }

        public AuthorizationContextException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}