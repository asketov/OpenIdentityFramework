using System.ComponentModel.DataAnnotations;

namespace OpenIdentityFramework.Host.Mvc.ViewModels;

public class LoginViewModel
{
    [Required]
    [MaxLength(100)]
    public string Login { get; set; } = null!;

    [Required]
    [MaxLength(100)]
    [DataType(DataType.Password)]
    public string Password { get; set; } = null!;

    public bool RememberMe { get; set; }
}
