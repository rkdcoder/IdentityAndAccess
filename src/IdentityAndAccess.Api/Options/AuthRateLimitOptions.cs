namespace IdentityAndAccess.Api.Options
{
    /// <summary>
    /// Limite de requisições por IP do endpoint de validação de credenciais (seção <c>RateLimiting:AuthValidate</c>).
    /// </summary>
    public sealed class AuthRateLimitOptions
    {
        public const string SectionName = "RateLimiting:AuthValidate";
        public const string PolicyName = "auth-validate";

        /// <summary>Requisições permitidas por IP em cada janela.</summary>
        public int PermitLimit { get; set; } = 10;

        /// <summary>Duração da janela, em segundos.</summary>
        public int WindowSeconds { get; set; } = 60;
    }
}
