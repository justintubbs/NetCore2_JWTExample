using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication1
{
    public static class TokenBuilder
    {
        public static readonly byte[] symmetricKeyBytes = Encoding.ASCII.GetBytes("mysuperdupersecret");
        public static readonly SymmetricSecurityKey symmetricKey = new SymmetricSecurityKey(symmetricKeyBytes);
        public static readonly SigningCredentials signingCredentials = new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256Signature);
        public static string CreateJsonWebToken(
               string username,
               IEnumerable<string> roles,
               string audienceUri,
               string issuerUri,
               Guid applicationId,
               DateTime expires,
               string deviceId = null,
               bool isReAuthToken = false)
        {
            var claims = new List<Claim>();
            if (roles != null)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }
            var head = new JwtHeader();
            var payload = new JwtPayload(claims.ToArray());
            var jwt = new JwtSecurityToken(issuerUri, audienceUri, claims, DateTime.UtcNow, expires, signingCredentials);
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }
}
