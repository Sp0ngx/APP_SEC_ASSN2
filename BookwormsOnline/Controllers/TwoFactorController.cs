using BookwormsOnline;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OtpNet;
using QRCoder;
using System.Security.Claims;

[AllowAnonymous]
[Route("TwoFactor")]
public class TwoFactorController : Controller
{
    private readonly ApplicationDbContext _context;

    public TwoFactorController(ApplicationDbContext context)
    {
        _context = context;
    }

    [HttpGet("Setup")]
    public async Task<IActionResult> Setup()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var user = await _context.Users.FindAsync(userId);
        if (user == null) return NotFound();

        if (string.IsNullOrEmpty(user.TwoFactorSecret))
        {
            var key = KeyGeneration.GenerateRandomKey(20);
            user.TwoFactorSecret = Base32Encoding.ToString(key);
            await _context.SaveChangesAsync();
        }

        string totpUri = $"otpauth://totp/BookwormsOnline:{user.Email}?secret={user.TwoFactorSecret}&issuer=BookwormsOnline";
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(totpUri, QRCodeGenerator.ECCLevel.Q);
        var qrCode = new Base64QRCode(qrCodeData);

        ViewBag.QRCodeImage = "data:image/png;base64," + qrCode.GetGraphic(20);
        ViewBag.Secret = user.TwoFactorSecret;

        return View();
    }

    [HttpPost("Toggle")]
    public async Task<IActionResult> Toggle()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var user = await _context.Users.FindAsync(userId);
        if (user == null) return NotFound();

        if (user.TwoFactorEnabled)
        {
            // Disable immediately
            user.TwoFactorEnabled = false;
            await _context.SaveChangesAsync();
            return Json(new { success = true, isEnabled = false });
        }

        // Enable requires verification
        if (string.IsNullOrEmpty(user.TwoFactorSecret))
        {
            var key = KeyGeneration.GenerateRandomKey(20);
            user.TwoFactorSecret = Base32Encoding.ToString(key);
            await _context.SaveChangesAsync();
        }

        // Generate QR code for Setup
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(
            $"otpauth://totp/BookwormsOnline:{user.Email}?secret={user.TwoFactorSecret}&issuer=BookwormsOnline",
            QRCodeGenerator.ECCLevel.Q
        );
        var qrCode = new Base64QRCode(qrCodeData);

        return Json(new
        {
            success = true,
            requiresVerification = true,
            qrCode = "data:image/png;base64," + qrCode.GetGraphic(20),
            secret = user.TwoFactorSecret
        });
    }

    [HttpPost("VerifyToggle")]
    public async Task<IActionResult> VerifyToggle(string code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return Json(new { success = false, message = "Please enter the 6-digit code from your authenticator." });

        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var user = await _context.Users.FindAsync(userId);
        if (user == null || string.IsNullOrEmpty(user.TwoFactorSecret))
            return Json(new { success = false, message = "Invalid user or secret." });

        try
        {
            var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
            if (!totp.VerifyTotp(code.Trim(), out _))
                return Json(new { success = false, message = "Invalid authentication code." });

            // Enable 2FA after correct code
            user.TwoFactorEnabled = true;
            await _context.SaveChangesAsync();
            return Json(new { success = true, isEnabled = true, message = "Two-Factor Authentication enabled!" });
        }
        catch
        {
            return Json(new { success = false, message = "Error verifying code. Make sure you entered 6 digits." });
        }
    }


    // If 2FA enabled, go to challeng pg
    [HttpGet("Challenge")]
    public IActionResult Challenge()
    {
        if (HttpContext.Session.GetInt32("2FAUserId") == null)
            return RedirectToAction("Login", "Login");

        return View();
    }

    [HttpPost("VerifyLogin")]
    public async Task<IActionResult> VerifyLogin(string code)
    {
        var userId = HttpContext.Session.GetInt32("2FAUserId");
        if (userId == null) return RedirectToAction("Login", "Login");

        var user = await _context.Users.FindAsync(userId.Value);
        if (user == null || string.IsNullOrEmpty(user.TwoFactorSecret))
            return RedirectToAction("Login", "Login");

        if (string.IsNullOrWhiteSpace(code))
        {
            TempData["Error"] = "Please enter your 6-digit code.";
            return RedirectToAction("Challenge");
        }

        var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorSecret));
        if (!totp.VerifyTotp(code.Trim(), out _))
        {
            TempData["Error"] = "Invalid authentication code.";
            return RedirectToAction("Challenge");
        }

        // Sign in after successful 2FA login
        var sessionToken = Guid.NewGuid().ToString();
        user.CurrentSessionToken = sessionToken;
        await _context.SaveChangesAsync();

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim("SessionToken", sessionToken)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        HttpContext.Session.Remove("2FAUserId");

        return RedirectToAction("Index", "Home");
    }

    [HttpGet("Status")]
    public async Task<IActionResult> Status()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var user = await _context.Users.FindAsync(userId);
        if (user == null) return Json(new { success = false });

        return Json(new
        {
            success = true,
            isEnabled = user.TwoFactorEnabled
        });
    }
}