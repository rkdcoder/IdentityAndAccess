namespace IdentityAndAccess.Identity.Application.Exceptions
{
    /// <summary>
    /// Nenhum controlador de domínio do Active Directory informado pôde ser alcançado/consultado.
    /// </summary>
    public sealed class DirectoryUnavailableException : Exception
    {
        public string Domain { get; }

        public DirectoryUnavailableException(string domain, Exception? innerException = null)
            : base("Não foi possível alcançar o Active Directory informado.", innerException)
        {
            Domain = domain;
        }
    }
}
