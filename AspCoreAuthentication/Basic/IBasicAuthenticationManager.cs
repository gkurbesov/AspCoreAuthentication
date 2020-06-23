using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace AspCoreAuthentication.Basic
{
    public interface IBasicAuthenticationManager
    {
        Task<bool> Authenticate(string username, string password);
    }
}
