using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    //Create Custom AuthenticationScheme
    public class EdDSAJwtBearerOptions : AuthenticationSchemeOptions
    {
        public string PublicSigningKey { get; set; }
        public bool ValidateIssuer { get; set; }
        public string ValidIssuer { get; set; } 
        public bool ValidateAudience { get; set; }
        public string ValidAudience { get; set; }
        public bool ValidateLifeTime { get; set; }
        public bool SaveToken { get; set; }
    }
}
 