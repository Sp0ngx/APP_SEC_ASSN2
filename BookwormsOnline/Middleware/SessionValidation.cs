using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace BookwormsOnline.Middleware
{
    public class SessionValidation
    {
        private readonly RequestDelegate _next;

        public SessionValidation(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ApplicationDbContext db)
        {
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var sessionTokenClaim = context.User.FindFirst("SessionToken")?.Value;

                if (int.TryParse(userIdClaim, out int userId) && sessionTokenClaim != null)
                {
                    var user = await db.Users.FindAsync(userId);

                    if (user == null || user.CurrentSessionToken != sessionTokenClaim)
                    {
                        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                        context.Response.Redirect("/Logout");
                        return;
                    }
                }
            }

            await _next(context);
        }
    }
}