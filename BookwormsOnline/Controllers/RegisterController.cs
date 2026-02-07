using BookwormsOnline.Models;
using BookwormsOnline.Models.ViewModels;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace BookwormsOnline.Controllers
{
    [Route("Register")]
    public class RegisterController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly EncryptionService _encryption;
        private readonly RecaptchaService _recaptchaService;
        private const long MaxPhotoSize = 5 * 1024 * 1024;


        public RegisterController(ApplicationDbContext context, EncryptionService encryption, RecaptchaService recaptchaService)
        {
            _context = context;
            _encryption = encryption;
            _recaptchaService = recaptchaService;
        }

        [HttpGet]
        public IActionResult Register()
        {
            ViewData["MaxPhotoSize"] = MaxPhotoSize;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, IFormFile photo)
        {
            if (!ModelState.IsValid)
                return View(model);

            var recaptchaValid = await _recaptchaService.Verify(model.RecaptchaToken, "register");

            if (!recaptchaValid)
            {
                ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                return View(model);
            }

            if (_context.Users.Any(u => u.Email == model.Email))
            {
                ModelState.AddModelError("Email", "Email is already registered.");
                return View(model);
            }

            // Generate salt
            byte[] saltBytes = new byte[8];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(saltBytes);
            string salt = Convert.ToBase64String(saltBytes);

            // Hash password + salt
            using var sha512 = SHA512.Create();
            string pwdWithSalt = model.Password + salt;
            byte[] hashBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(pwdWithSalt!));
            string finalHash = Convert.ToBase64String(hashBytes);

            var ext = Path.GetExtension(photo.FileName).ToLower();
            if (ext != ".jpg")
            {
                ModelState.AddModelError("Photo", "Only .JPG files are allowed.");
                return View(model);
            }

            if (photo.Length > MaxPhotoSize)
            {
                ModelState.AddModelError("Photo", "Photo size cannot exceed 5 MB.");
                return View(model);
            }

            var user = new ApplicationUser
            {
                Email = WebUtility.HtmlEncode(model.Email),
                FirstName = WebUtility.HtmlEncode(model.FirstName),
                LastName = WebUtility.HtmlEncode(model.LastName),
                PasswordHash = finalHash,
                Salt = salt,
                PasswordChangedAt = DateTime.UtcNow,
                EncryptedCreditCard = _encryption.Encrypt(model.CreditCardNo),
                MobileNo = model.MobileNo,
                BillingAddress = WebUtility.HtmlEncode(model.BillingAddress),
                ShippingAddress = WebUtility.HtmlEncode(model.ShippingAddress)
            };

            // Photo upload
            if (photo != null && photo.Length > 0)
            {
                var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/images/users");
                Directory.CreateDirectory(uploadsFolder);
                var fileName = Guid.NewGuid() + Path.GetExtension(photo.FileName);
                var filePath = Path.Combine(uploadsFolder, fileName);
                using var stream = new FileStream(filePath, FileMode.Create);
                await photo.CopyToAsync(stream);
                user.PhotoPath = "/images/users/" + fileName;
            }

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return RedirectToAction("Index", "Home");
        }
    }
}