using Microsoft.EntityFrameworkCore;
using BookwormsOnline;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using BookwormsOnline.Middleware;

var builder = WebApplication.CreateBuilder(args);

var sessionTimeoutMinutes = 5;
var warningBeforeMinutes = 1;

builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<EncryptionService>();
builder.Services.AddScoped<RecaptchaService>();
builder.Services.AddScoped<EmailService>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(sessionTimeoutMinutes);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Login";
        options.LogoutPath = "/Login/Logout";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(sessionTimeoutMinutes);
        options.SlidingExpiration = true;
        options.AccessDeniedPath = "/Home/Error/403";
    });

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Items["SessionTimeoutMinutes"] = sessionTimeoutMinutes;
    context.Items["WarningBeforeMinutes"] = warningBeforeMinutes;
    await next();
});

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseRouting();

app.UseSession();

app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<SessionValidation>();
app.UseMiddleware<PasswordExpiryMiddleware>();

app.UseStatusCodePagesWithReExecute("/Home/Error/{0}");


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();