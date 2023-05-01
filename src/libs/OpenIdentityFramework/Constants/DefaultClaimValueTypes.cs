using System.Security.Claims;

namespace OpenIdentityFramework.Constants;

public static class DefaultClaimValueTypes
{
    public const string Boolean = ClaimValueTypes.Boolean;
    public const string Integer32 = ClaimValueTypes.Integer32;
    public const string Integer64 = ClaimValueTypes.Integer64;
    public const string UInteger32 = ClaimValueTypes.UInteger32;
    public const string UInteger64 = ClaimValueTypes.UInteger64;
    public const string DateTime = ClaimValueTypes.DateTime;
    public const string Json = "json";
#pragma warning disable CA1720
    public const string Integer = ClaimValueTypes.Integer;
    public const string String = ClaimValueTypes.String;
#pragma warning restore CA1720
}
