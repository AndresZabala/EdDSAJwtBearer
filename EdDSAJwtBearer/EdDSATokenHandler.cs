using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    public static class EdDSATokenHandler
    {
        public static string CreateToken(Dictionary<string, object> payload, string edDSAPrivateKey)
        {
            var HeaderValues = new Dictionary<string, object>
            {
                { "alg", "EdDSA"},
                { "typ", "JWT"}
            };

            string Header = JsonSerializer.Serialize(HeaderValues);
            string Payload = JsonSerializer.Serialize(payload);

            //Puede contener caracteres que no son transportables en peticiones HTTP
            //Se debe codificar a Base64Url
            Header = Base64UrlEncode(Header);
            Payload = Base64UrlEncode(Payload);

            //Obtener la firma del Token
            string Signature = GetJWTSignature(Header, Payload, edDSAPrivateKey);
            return $"{Header}.{Payload}.{Signature}";
        }

        private static string GetJWTSignature(string header, string payload, string edDSAPrivateKey)
        {
            string SignatureData = $"{header}.{payload}";
            var SignatureBytes = Encoding.UTF8.GetBytes(SignatureData);
            var Signer = new Ed25519Signer();
            Signer.Init(true, GetDerDecodedAsymmetricPrivateKeyParameter(edDSAPrivateKey));
            Signer.BlockUpdate(SignatureBytes, 0, SignatureBytes.Length);
            return Base64UrlEncode(Signer.GenerateSignature());
        }

        private static AsymmetricKeyParameter GetDerDecodedAsymmetricPrivateKeyParameter(string edDSAPrivateKey)
            => PrivateKeyFactory.CreateKey(Convert.FromBase64String(edDSAPrivateKey));

        private static AsymmetricKeyParameter GetDerDecodedAsymmetricPublicKeyParameter(string edDSAPublicKey)
            => PublicKeyFactory.CreateKey(Convert.FromBase64String(edDSAPublicKey));

        private static AsymmetricCipherKeyPair GetDerDecodedAsymmetricCipherKeyPair(EdDSAKeys key)
        {
            var PrivateKey = GetDerDecodedAsymmetricPrivateKeyParameter(key.Private);
            var PublicKey = GetDerDecodedAsymmetricPublicKeyParameter(key.Public);
            return new AsymmetricCipherKeyPair(PublicKey, PrivateKey);
        }


        private static EdDSAKeys GetDerEncodedAsymmetricCipherKeyPair(AsymmetricCipherKeyPair keys)
        {
            EdDSAKeys EdDSAKeys = new EdDSAKeys();

            var PrivateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keys.Private);
            byte[] Buffer = PrivateKeyInfo.ToAsn1Object()
                .GetDerEncoded();
            EdDSAKeys.Private = Convert.ToBase64String(Buffer);

            var SubjectPublicKeyInfo = SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(keys.Public);

            Buffer = SubjectPublicKeyInfo.ToAsn1Object().GetDerEncoded();
            EdDSAKeys.Public = Convert.ToBase64String(Buffer);
            return EdDSAKeys;
        }


        public static string CreateToken(string edDSAPrivateKey, string issuer = null, string audiencie = null, IEnumerable<Claim> claims = null, string[] roles = null, DateTime? expires = null)
        {
            Dictionary<string, object> Payload = new Dictionary<string, object>();
            if (claims != null)
            {
                foreach (var item in claims)
                {
                    Payload.TryAdd(item.Type, item.Value);
                }
            }
            if (issuer != null) Payload.Add("iss", issuer);
            if (audiencie != null) Payload.Add("aud", audiencie);
            if (expires != null) Payload.Add("exp", new DateTimeOffset(expires.Value).ToUnixTimeSeconds());
            if (roles != null && roles.Length > 0) Payload.Add("role", roles);
            return CreateToken(Payload, edDSAPrivateKey);
        }

        private static AsymmetricCipherKeyPair CreateKeys()
        {
            var KeyPairGenerator = new Ed25519KeyPairGenerator();
            KeyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            return KeyPairGenerator.GenerateKeyPair();
        }

        public static EdDSAKeys CreateDerEncodeKeys() => GetDerEncodedAsymmetricCipherKeyPair(CreateKeys());


        public static bool VerifySignature(string token, string edDSAPublicKey)
        {
            bool Result = false;
            try
            {
                string[] JWTParts = token.Split(".");
                if (JWTParts.Length == 3)
                {
                    string Data = $"{JWTParts[0]}.{JWTParts[1]}";
                    byte[] DataBytes = Encoding.UTF8.GetBytes(Data);
                    byte[] Signature = Base64UrlDecode(JWTParts[2]);

                    var Validator = new Ed25519Signer();
                    Validator.Init(false, GetDerDecodedAsymmetricPublicKeyParameter(edDSAPublicKey));
                    Validator.BlockUpdate(DataBytes,0 ,DataBytes.Length);
                    Result = Validator.VerifySignature(Signature);
                }
            }
            catch 
            {
                //Logica para cuando el token no puede ser verificado                
            }
            return Result;
        }

        public static bool TryGetPayloadFromToken(string token, string edDSAPublicKey, out Dictionary<string, object> payload)
        {
            bool Result = false; payload = null;

            try
            {
                if (VerifySignature(token, edDSAPublicKey))
                {
                    string PayloadData = token.Split(".")[1];
                    string JSONPayload = Encoding.UTF8.GetString(Base64UrlDecode(PayloadData));

                    payload = JsonSerializer.Deserialize<Dictionary<string, object>>(JSONPayload);
                    Result = true;
                }
            }
            catch
            {
                //Logica para cuando el token no se puede generar
            }

            return Result;
        }


        public static string Base64UrlEncode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg);
            s = s.Split('=')[0]; //Remove any trailing '=' s
            s = s.Replace('+', '-'); //62nd char of encoding 
            s = s.Replace('/', '_'); //63rd char of encoding
            return s;
        }

        public static string Base64UrlEncode(string data)
        {
            byte[] DataBytes = Encoding.UTF8.GetBytes(data);
            return Base64UrlEncode(DataBytes);
        }

        public static byte[] Base64UrlDecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); //62nd char of encoding
            s = s.Replace('_', '/'); //63rd char of encoding
            switch (s.Length % 4)
            {
                case 0: break; // No pad chars in this case 
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new System.Exception("Illegal base64url string!");                        
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        } 
    }
}
