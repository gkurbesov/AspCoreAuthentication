using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace AspCoreAuthentication.Bearer
{
    public interface IBearerAuthenticationManager
    {
        Task<bool> ValidateToken(string token);
        Task<(bool result, string token)> Authenticate(string username, string password);
    }
}
