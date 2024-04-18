using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ClientLibrary.Helpers
{
    public class CustomAuthenticationStateProvider(LocalStorageService localStorageService) : AuthenticationStateProvider
    {
        private readonly ClaimsPrincipal anonymous = new (new ClaimsPrincipal());   
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var stringToken = await localStorageService.GetToken();
            if (string.IsNullOrEmpty(stringToken))  return await Task.FromResult(new AuthenticationState(anonymous));

            var deserializeToken = Serializations.DeserializeJsonString<UserSession>(stringToken);
            if (deserializeToken == null) return await Task.FromResult(new AuthenticationState(anonymous));

            var getUserClaims = DecryptToken(deserializeToken.Token!);
            if (getUserClaims == null) return await Task.FromResult(new AuthenticationState(anonymous));

            var claimsPrinciple = SetClaimPrincipal(getUserClaims);
            return await Task.FromResult(new AuthenticationState(claimsPrinciple));

        }

        public async Task UpdateAuthenticationState(UserSession userSession)
        {
            var claimsPrincipal = new ClaimsPrincipal();
            if(userSession.Token != null || userSession.RefreshToken != null) 
            {
                var serializeSession = Serializations.SerializeObj(userSession);
                await localStorageService.SetToken(serializeSession);
                var getUserClaims = DecryptToken(userSession.Token!);
                claimsPrincipal = SetClaimPrincipal(getUserClaims);

            }
            else
            {
                await localStorageService.RemoveToken();
            }
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        public static ClaimsPrincipal SetClaimPrincipal(CustomerUserClaims claims)
        {
            if (claims.Email == null) return new ClaimsPrincipal();
            return new ClaimsPrincipal(new ClaimsIdentity(
                new List<Claim>
                {
                    new (ClaimTypes.NameIdentifier, claims.Id!),
                    new (ClaimTypes.Name, claims.Name!),
                    new (ClaimTypes.Email,claims.Email),
                    new (ClaimTypes.Role,claims.Role),
                },"JwtAuth"));
        }

        private static CustomerUserClaims DecryptToken(string jwtToken)
        {
            if(string.IsNullOrEmpty(jwtToken)) return new CustomerUserClaims();

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtToken);

            var userId = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.NameIdentifier);
            var name = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Name);
            var email = token.Claims.FirstOrDefault(_ => _.Type == ClaimTypes.Email);
            var role = token.Claims.FirstOrDefault(_=> _.Type == ClaimTypes.Role);
            return new CustomerUserClaims(userId!.Value, name!.Value, email!.Value, role!.Value);

        }
    }
}
