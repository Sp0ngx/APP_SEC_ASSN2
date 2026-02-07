using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models.ViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "First name is required.")]
        [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters.")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required.")]
        [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters.")]
        public string LastName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [DataType(DataType.EmailAddress)]
        [StringLength(100)]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Credit Card Number is required.")]
        [CreditCard(ErrorMessage = "Invalid credit card number.")]
        [DataType(DataType.CreditCard)]
        [StringLength(16, MinimumLength = 13)]
        public string CreditCardNo { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mobile number is required.")]
        [Phone(ErrorMessage = "Invalid phone number.")]
        [RegularExpression(@"^\+?\d{7,15}$", ErrorMessage = "Mobile number must be 7 to 15 digits.")]
        public string MobileNo { get; set; } = string.Empty;

        [Required(ErrorMessage = "Billing address is required.")]
        [StringLength(200)]
        public string BillingAddress { get; set; } = string.Empty;

        [Required(ErrorMessage = "Shipping address is required.")]
        [RegularExpression(@"^[\w\s.,#\-@&/]+$", ErrorMessage = "Shipping address contains invalid characters.")]
        [StringLength(200)]
        public string ShippingAddress { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$",
            ErrorMessage = "Password must contain at least one lowercase letter, one uppercase letter, one number and one special character."
            )]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Confirm password is required.")]
        [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Profile photo is required.")]
        [DataType(DataType.Upload)]
        public IFormFile Photo { get; set; } = null!;
    }
}