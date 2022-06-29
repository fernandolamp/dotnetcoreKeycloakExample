# Dotnet core multiple scheme Auth and keycloak example

Objective: Create a example using multiple scheme with authorize attribute using keycloak, just for study purpose.

## How to run

run docker compose to setup keycloak

Import the file `realm-export.json` to configure keycloak.

This file will create 2 realms:  
  * realm1 with teste2 clientId
  * realm2 with teste and backend clientId

test2 and teste client ID is just for generate token using basic authentication.

backend is used to use stadand flow and confidential access type.


You need to create a user for both realms on keycloak.

# How this work

TestController  has 3 methods:
```csharp        
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
```        

The first method use default scheme authorization (realm1)

The second method use `keycloak_realm2`scheme authorization (realm2)

The third method use `standard flow` authorization(realm1, clientId 1).

# How to test

(Insominia file v4 is in the root folder)

To acess the first and second endpoint, is necessary generate a acess token.

To generate token do a post request to keycloak with form url encode:

http://localhost:8080/auth/realms/realm1/protocol/openid-connect/token

grant_type:password

client_id:teste

username: `<your user name>`

password: `<your password>`

Use the token on swagger (Authorize button), don't forget to use the bearer prefix.

To acess the second endpoint, just change the realm(url) and clientId before generate token.

To acess  the third acess point, just acess the adress on browser: https://localhost:7194/api/Teste/authRealm3

You will be redirect to a login page and return do endpoint url after login.

