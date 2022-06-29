using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web.Resource;
using System.Net;

namespace AutenticacaoTeste.Controllers
{
    [Route("api/[controller]")]
    [Authorize]
    [ApiController]
    
    public class TesteController : ControllerBase
    {
        //usa o default scheme de autenticação
        [HttpGet]
        public async Task<HttpResponseMessage> Get()
        {
            return new HttpResponseMessage(HttpStatusCode.OK);
        }

        [Authorize(AuthenticationSchemes= "keycloak_realm2")]
        [HttpGet]
        [Route("authRealm2")]
        public async Task<HttpResponseMessage> Get2()
        {
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
        [Authorize(AuthenticationSchemes = "oidc")]
        [HttpGet]
        [Route("OpenIDStandardFlow")]
        public async Task<HttpResponseMessage> Get3()
        {
            return new HttpResponseMessage(HttpStatusCode.OK);
        }


    }
}
