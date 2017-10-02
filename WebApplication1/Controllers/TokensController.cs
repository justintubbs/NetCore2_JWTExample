using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    [Produces("application/json")]
    [Route("api/v1/tokens")]
    public class TokensController : Controller
    {
        [HttpGet]
        [Authorize] // Throws WWW-Authenticate: Bearer error="invalid_token", error_description="The signature is invalid"
        public IActionResult Get()
        {
            return Ok();
        }
        
        [HttpPost]
        public IActionResult Post()
        {
            var model = TokenBuilder.CreateJsonWebToken("justin.tubbs", new List<string>() { "Administrator" } , "http://audience.com", "http://issuer.com", Guid.NewGuid(), DateTime.UtcNow.AddMinutes(20));
            return Ok(model);
        }
    }
}