using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AspCoreAuthentication.Basic
{
    public interface IBasicAuthenticationManager
    {
        Task<bool> Authenticate(string username, string password);
        Task<ClaimsIdentity> CreateIdentity(string username, string password, string schemename);
    }
}
