using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}
