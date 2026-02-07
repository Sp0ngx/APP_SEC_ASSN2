using BookwormsOnline;
using BookwormsOnline.Models;
using BookwormsOnline.Models.ViewModels;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

[Route("PasswordReset")]
public class PasswordResetController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly EmailService _email;

    public PasswordResetController(ApplicationDbContext context, EmailService email)
    {
        _context = context;
        _email = email;
    }

    [HttpGet("Forgot")]
    public IActionResult Forgot() => View();

    [HttpPost("Forgot")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Forgot(ForgotPasswordViewModel model)
    {
        var user = _context.Users.SingleOrDefault(u => u.Email == model.Email);
        if (user == null) return RedirectToAction("ForgotConfirmation");

        var token = Guid.NewGuid().ToString();
        _context.PasswordResetTokens.Add(new PasswordResetToken
        {
            UserId = user.Id,
            Token = token,
            Expiry = DateTime.UtcNow.AddHours(1)
        });
        await _context.SaveChangesAsync();

        var resetLink = Url.Action("Reset", "PasswordReset", new { token }, Request.Scheme);
        await _email.SendEmailAsync(user.Email, "Password Reset", $"Click here to reset: {resetLink}");

        return RedirectToAction("ForgotConfirmation");
    }

    [HttpGet("Reset")]
    public IActionResult Reset(string token) => View(new ResetPasswordViewModel { Token = token });

    [HttpPost("Reset")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Reset(ResetPasswordViewModel model)
    {
        var resetToken = _context.PasswordResetTokens
            .SingleOrDefault(t => t.Token == model.Token && t.Expiry > DateTime.UtcNow);

        if (resetToken == null)
        {
            ModelState.AddModelError("", "Invalid or expired token");
            return View(model);
        }

        var user = await _context.Users.FindAsync(resetToken.UserId);
        if (user == null) return NotFound();

        var newHash = HashPassword(model.NewPassword, user.Salt);

        // Check last 2 passwords
        var lastTwo = _context.PasswordHistories
            .Where(p => p.UserId == user.Id.ToString())
            .OrderByDescending(p => p.CreatedAt)
            .Take(2)
            .Select(p => p.PasswordHash)
            .ToList();

        if (lastTwo.Any(p => p == newHash))
        {
            ModelState.AddModelError("", "Cannot reuse last 2 passwords.");
            return View(model);
        }

        user.PasswordHash = newHash;
        user.PasswordChangedAt = DateTime.UtcNow;

        _context.PasswordHistories.Add(new PasswordHistory
        {
            UserId = user.Id.ToString(),
            PasswordHash = newHash,
            CreatedAt = DateTime.UtcNow
        });

        // Delete token after use
        _context.PasswordResetTokens.Remove(resetToken);

        await _context.SaveChangesAsync();
        TempData["Success"] = "Password reset successfully!";
        return RedirectToAction("Login", "Login");
    }

    private string HashPassword(string password, string salt)
    {
        using var sha512 = SHA512.Create();
        var bytes = Encoding.UTF8.GetBytes(password + salt);
        return Convert.ToBase64String(sha512.ComputeHash(bytes));
    }

    [HttpGet("ForgotConfirmation")]
    public IActionResult ForgotConfirmation()
    {
        return View();
    }
}