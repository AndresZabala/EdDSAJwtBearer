using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerServerOptions 
    {
        public string Audience { get; set; }
        public string Issuer { get; set; } //Quien va dirigio quien genera el token
        public string PrivateSigningKey { get; set; } //LLave privada para generar el token
        public string PublicSigningKey { get; set; }  //Llave publica para firmar
    }
}
