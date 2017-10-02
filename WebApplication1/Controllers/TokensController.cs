using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication1.Controllers
{
    public class TokensController : Controller
    {
        [HttpGet]
        [Route("api/v1/tokens")]
        [Authorize] // Throws WWW-Authenticate: Bearer error="invalid_token", error_description="The signature is invalid"
        public IActionResult Get()
        {
            return Ok();
        }

        [HttpGet]
        [Route("api/v1/tokens2")]
        [AllowAnonymous]
        public IActionResult Get2()
        {
            var authenticationHeaders = Request.Headers["Authorization"].ToArray();
            if ((authenticationHeaders == null) || (authenticationHeaders.Length != 1))
            {
                return BadRequest();
            }
            var jwToken = authenticationHeaders[0].Split(' ')[1];
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = null;
            SecurityToken securityToken = null;
            try
            {
                principal = jwtSecurityTokenHandler.ValidateToken(jwToken, TokenBuilder.tokenValidationParams, out securityToken);
            }
            catch (Exception ex)
            {
                throw ex;
            }
            if ((principal != null) && (principal.Claims != null))
            {
                var jwtSecurityToken = securityToken as JwtSecurityToken;
                Trace.WriteLine(jwtSecurityToken.Audiences.First());
                Trace.WriteLine(jwtSecurityToken.Issuer);
            }
            return Ok();
        }
        
        [HttpPost]
        [Route("api/v1/tokens")]
        public IActionResult Post()
        {
            var model = TokenBuilder.CreateJsonWebToken("justin.tubbs", new List<string>() { "Administrator" } , "http://audience.com", "http://issuer.com", Guid.NewGuid(), DateTime.UtcNow.AddMinutes(20));
            return Ok(model);
        }
    }
}