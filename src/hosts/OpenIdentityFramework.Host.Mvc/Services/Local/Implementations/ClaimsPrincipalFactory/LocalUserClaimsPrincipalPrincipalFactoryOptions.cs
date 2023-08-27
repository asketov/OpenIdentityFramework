namespace OpenIdentityFramework.Host.Mvc.Services.Local.Implementations.ClaimsPrincipalFactory;

public class LocalUserClaimsPrincipalPrincipalFactoryOptions
{
    public string AuthenticationType { get; set; } = null!;
    public string NameClaimType { get; set; } = null!;
    public string RoleClaimType { get; set; } = null!;
}
