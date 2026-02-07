using BookwormsOnline;
using BookwormsOnline.Models;
using BookwormsOnline.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

[Authorize]
[Route("ChangePassword")]
public class ChangePasswordController : Controller
{
    private readonly ApplicationDbContext _context;

    public ChangePasswordController(ApplicationDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public IActionResult Index(bool expired = false)
    {
        if (expired)
            TempData["Warning"] = "Your password has expired. Please change it to continue.";
        return View(new ChangePasswordViewModel());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var user = await _context.Users.FindAsync(userId);
        if (user == null) return NotFound();

        int minAgeMinutes = 1;

        var passwordAgeMinutes = (DateTime.UtcNow - user.PasswordChangedAt).TotalMinutes;

        if (passwordAgeMinutes < minAgeMinutes)
        {
            ModelState.AddModelError("", "You must wait at least 1 minute before changing your password again.");
            return View(model);
        }

        // Verify old password
        if (!VerifyPassword(model.OldPassword, user.Salt, user.PasswordHash))
        {
            ModelState.AddModelError("", "Old password is incorrect.");
            return View(model);
        }

        // Hash new password
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

        // Update password and save
        user.PasswordHash = newHash;
        user.PasswordChangedAt = DateTime.UtcNow;

        _context.PasswordHistories.Add(new PasswordHistory
        {
            UserId = user.Id.ToString(),
            PasswordHash = newHash,
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();

        TempData["Success"] = "Password changed successfully!";
        return RedirectToAction("Index", "Home");
    }

    private bool VerifyPassword(string enteredPassword, string salt, string storedHash)
    {
        using var sha512 = SHA512.Create();
        var hash = sha512.ComputeHash(Encoding.UTF8.GetBytes(enteredPassword + salt));
        return Convert.ToBase64String(hash) == storedHash;
    }

    private string HashPassword(string password, string salt)
    {
        using var sha512 = SHA512.Create();
        return Convert.ToBase64String(sha512.ComputeHash(Encoding.UTF8.GetBytes(password + salt)));
    }
}