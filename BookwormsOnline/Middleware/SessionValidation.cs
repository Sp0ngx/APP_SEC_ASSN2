using Microsoft.AspNetCore.Authentication;
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
            // Check if user is authenticated
            if (context.User.Identity.IsAuthenticated)
            {
                var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var sessionTokenClaim = context.User.FindFirst("SessionToken")?.Value;

                if (userIdClaim != null && sessionTokenClaim != null)
                {
                    int userId = int.Parse(userIdClaim);
                    var user = await db.Users.FindAsync(userId);

                    // Compare token in DB with token in cookie
                    if (user == null || user.CurrentSessionToken != sessionTokenClaim)
                    {
                        // Sign out if session is invalid (another device logged in)
                        await context.SignOutAsync();
                        context.Response.Redirect("/Login");
                        return;
                    }
                }
            }

            // Call the next middleware in the pipeline
            await _next(context);
        }
    }
}