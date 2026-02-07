using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

public class EncryptionService
{
    private readonly string _key;

    public EncryptionService(IConfiguration configuration)
    {
        _key = configuration["Encryption:Key"];

        if (Encoding.UTF8.GetBytes(_key).Length != 32)
            throw new ArgumentException("Encryption key must be exactly 32 characters.");
    }

    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(_key);
        aes.GenerateIV();

        var encryptor = aes.CreateEncryptor();
        var bytes = Encoding.UTF8.GetBytes(plainText);
        var encrypted = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);

        return Convert.ToBase64String(aes.IV) + ":" +
               Convert.ToBase64String(encrypted);
    }

    public string Decrypt(string cipherText)
    {
        var parts = cipherText.Split(':');
        if (parts.Length != 2)
            throw new FormatException("Invalid encrypted text format");

        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(_key);
        aes.IV = Convert.FromBase64String(parts[0]);

        var decryptor = aes.CreateDecryptor();
        var bytes = Convert.FromBase64String(parts[1]);

        return Encoding.UTF8.GetString(
            decryptor.TransformFinalBlock(bytes, 0, bytes.Length));
    }
}