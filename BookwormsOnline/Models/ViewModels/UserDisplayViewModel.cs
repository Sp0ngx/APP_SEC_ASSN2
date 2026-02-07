namespace BookwormsOnline.Models.ViewModels
{
    public class UserDisplayViewModel
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string CreditCardNo { get; set; } = string.Empty;
        public string MobileNo { get; set; } = string.Empty;
        public string BillingAddress { get; set; } = string.Empty;
        public string ShippingAddress { get; set; } = string.Empty;
    }
}