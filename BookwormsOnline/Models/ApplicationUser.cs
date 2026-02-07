public class ApplicationUser
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Salt { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string EncryptedCreditCard { get; set; } = string.Empty;
    public string MobileNo { get; set; } = string.Empty;
    public string BillingAddress { get; set; } = string.Empty;
    public string ShippingAddress { get; set; } = string.Empty;
    public string? PhotoPath { get; set; }
    public DateTime PasswordChangedAt { get; set; }

    public string? CurrentSessionToken { get; set; }

    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }

    public bool TwoFactorEnabled { get; set; } = false;
    public string? TwoFactorSecret { get; set; }

}