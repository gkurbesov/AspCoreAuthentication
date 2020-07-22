using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AspCoreAuthentication.Bearer
{
    public interface IBearerAuthenticationManager
    {
        Task<bool> ValidateToken(string token);
        Task<(bool result, string token)> Authenticate(string username, string password);
        Task<ClaimsIdentity> CreateIdentity(string token, string schemename);
    }
}
