using BookwormsOnline.Models;
using BookwormsOnline.Models.ViewModels;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace BookwormsOnline.Controllers
{
    [Route("Login")]
    public class LoginController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly RecaptchaService _recaptchaService;

        public LoginController(ApplicationDbContext context, RecaptchaService recaptchaService)
        {
            _context = context;
            _recaptchaService = recaptchaService;
        }

        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            // Verify reCAPTCHA token
            var recaptchaValid = await _recaptchaService.Verify(model.RecaptchaToken, "login");
            if (!recaptchaValid)
            {
                ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                return View(model);
            }

            var user = _context.Users.SingleOrDefault(u => u.Email == model.Email);

            // Check if account is locked
            if (user != null && user.LockoutEnd != null && user.LockoutEnd > DateTime.UtcNow)
            {
                ModelState.AddModelError("", $"Account is locked until {user.LockoutEnd.Value.ToLocalTime()}");
                return View(model);
            }

            // Check password
            if (user == null || !VerifyPassword(model.Password, user.Salt, user.PasswordHash))
            {
                if (user != null)
                {
                    user.FailedLoginAttempts++;

                    if (user.FailedLoginAttempts >= 3)
                        user.LockoutEnd = DateTime.UtcNow.AddMinutes(1); // lockout time

                    await _context.SaveChangesAsync();
                }

                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }

            // Reset failed attempts on successful login
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            await _context.SaveChangesAsync();

            // Check if 2FA is enabled
            if (user.TwoFactorEnabled)
            {
                HttpContext.Session.SetInt32("2FAUserId", user.Id);
                return RedirectToAction("Challenge", "TwoFactor");
            }

            // Generate a new session token for this login
            var sessionToken = Guid.NewGuid().ToString();
            user.CurrentSessionToken = sessionToken;
            await _context.SaveChangesAsync();

            // Create claims for cookie auth
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim("SessionToken", sessionToken)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            var log = new AuditLog
            {
                UserEmail = user.Email,
                Action = "Login",
                Timestamp = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();

            HttpContext.Session.SetString("UserId", user.Id.ToString());

            return RedirectToAction("Index", "Home");
        }

        [HttpGet("/Logout")]
        public async Task<IActionResult> Logout()
        {
            // Sign out the user from cookie authentication
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Clear session
            HttpContext.Session.Clear();

            var userEmail = User.Identity.IsAuthenticated ? User.FindFirst(ClaimTypes.Email)?.Value : "Unknown";

            var log = new AuditLog
            {
                UserEmail = userEmail ?? "Unknown",
                Action = "Logout",
                Timestamp = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();

            return RedirectToAction("Login");
        }

        private bool VerifyPassword(string enteredPassword, string storedSalt, string storedHash)
        {
            string pwdWithSalt = enteredPassword + storedSalt;

            using var sha512 = SHA512.Create();
            byte[] hashBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt));
            string finalHash = Convert.ToBase64String(hashBytes);

            return finalHash == storedHash;
        }
    }
}