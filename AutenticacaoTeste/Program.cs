using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.Resource;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace AutenticacaoTeste
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = "keycloak_realm1";
                options.DefaultChallengeScheme = "keycloak_realm1";

            })
            .AddCookie(options =>
            {
                options.CookieManager = new ChunkingCookieManager();
                options.Cookie.HttpOnly = false;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                
            })
            .AddOpenIdConnect("oidc",options =>
            {
                options.Authority = "http://localhost:8080/auth/realms/realm1";
                options.ClientId = "backend";
                options.RequireHttpsMetadata = false;
                options.ClientSecret = "kkVApLEKj35OCfyxPfAr6Ht13gNyi8B8";
                options.ResponseType = "code";                                
                options.SaveTokens = true;
            })
            .AddJwtBearer("keycloak_realm1", options =>
            {
                options.Authority = "http://localhost:8080/auth/realms/realm1";
                options.Audience = "account";
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidIssuer = "http://localhost:8080/auth/realms/realm1",
                    ValidAudience = "account",
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero
                };
            })
            .AddJwtBearer("keycloak_realm2", options =>
            {
                options.Authority = "http://localhost:8080/auth/realms/realm2";
                options.Audience = "teste2";
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidIssuer = "http://localhost:8080/auth/realms/realm2",
                    ValidAudience = "account",
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero
                };
            })
            .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));



            builder.Services.AddControllers();
           

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen( opt =>
            {
                opt.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter into field the word 'Bearer' following by space and JWT",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });
                opt.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new List<string>()
                    }
                });
            });
           

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }            

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}