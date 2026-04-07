namespace Platform.Identity.Abstractions.Options
{
    public sealed class DirectoryServicesOptions
    {
        /// <summary>
        /// Flags padrão para a validação. Ex.: "Negotiate"
        /// </summary>
        public string ContextOptions { get; set; } = "Negotiate";

        /// <summary>
        /// Timeout de chamadas ao AD (segundos).
        /// </summary>
        public int TimeoutSeconds { get; set; } = 10;
    }
}