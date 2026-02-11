using BookwormsOnline.Models;
using BookwormsOnline.Models.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Security.Claims;

namespace BookwormsOnline.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ApplicationDbContext _context;
        private readonly EncryptionService _encryption;

        public HomeController(ILogger<HomeController> logger, ApplicationDbContext context, EncryptionService encryption)
        {
            _logger = logger;
            _context = context;
            _encryption = encryption;
        }

        public IActionResult Index()
        {
            if (!User.Identity!.IsAuthenticated)
                return RedirectToAction("Login", "Login");

            var email = User.FindFirstValue(ClaimTypes.Email);
            var token = User.FindFirstValue("SessionToken");

            var user = _context.Users.SingleOrDefault(u => u.Email == email);

            if (user == null)
                return RedirectToAction("Error", new { code = 404 });

            // Detect multiple logins (session token mismatch)
            if (user.CurrentSessionToken != token)
            {
                HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                TempData["Error"] = "You have been logged out because your account was logged in from another device.";
                return RedirectToAction("Login", "Login");
            }

            var fullCardNumber = _encryption.Decrypt(user.EncryptedCreditCard);

            string maskedCardNumber = "**** **** **** " + fullCardNumber.Substring(fullCardNumber.Length - 4);


            var model = new UserDisplayViewModel
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                CreditCardNo = maskedCardNumber,
                MobileNo = user.MobileNo,
                BillingAddress = user.BillingAddress,
                ShippingAddress = user.ShippingAddress,
                PhotoPath = user.PhotoPath
            };

            return View(model);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        // Error handling
        [AllowAnonymous]
        [Route("Home/Error/{code?}")]
        public IActionResult Error(int? code = null)
        {
            var model = new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            };

            if (code != null)
            {
                switch (code.Value)
                {
                    case 404:
                        model.Message = "Sorry, the page you requested could not be found.";
                        return View("404", model);
                    case 403:
                        model.Message = "You are not authorized to access this page.";
                        return View("403", model);
                    default:
                        model.Message = "An unexpected error occurred.";
                        break;
                }
            }

            return View(model);
        }

        [Authorize]
        [HttpGet]
        public IActionResult KeepAlive()
        {
            return Ok();
        }

    }
}