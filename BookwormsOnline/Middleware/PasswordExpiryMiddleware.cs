using Microsoft.AspNetCore.Http;
using BookwormsOnline;
using Microsoft.EntityFrameworkCore;

public class PasswordExpiryMiddleware
{
    private readonly RequestDelegate _next;
    private readonly int _maxAgeMinutes = 30;

    public PasswordExpiryMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ApplicationDbContext db)
    {
        if (context.User.Identity != null && context.User.Identity.IsAuthenticated)
        {
            var userIdClaim = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userIdClaim))
            {
                var user = await db.Users.FindAsync(int.Parse(userIdClaim));
                if (user != null)
                {
                    var passwordAgeMinutes = (DateTime.UtcNow - user.PasswordChangedAt).TotalMinutes;

                    // Allow these paths even if password expired
                    if (passwordAgeMinutes > _maxAgeMinutes &&
                        !context.Request.Path.StartsWithSegments("/ChangePassword", StringComparison.OrdinalIgnoreCase) &&
                        !context.Request.Path.StartsWithSegments("/Logout", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.Redirect("/ChangePassword?expired=true");
                        return;
                    }
                }
            }
        }

        await _next(context);
    }
}