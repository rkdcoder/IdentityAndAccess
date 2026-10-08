using System.ComponentModel.DataAnnotations;

namespace IdentityAndAccess.Api.Models;

public sealed class ValidateCredentialsRequest
{
    /// <summary>Usuário (sAMAccountName ou UPN).</summary>
    [Required(ErrorMessage = "O usuário não pode ser vazio.")]
    [MaxLength(256, ErrorMessage = "O usuário deve ter no máximo 256 caracteres.")]
    public string Username { get; init; } = string.Empty;

    [Required(ErrorMessage = "A senha não pode ser vazia.")]
    public string Password { get; init; } = string.Empty;

    /// <summary>Domínio (ou IP do controlador de domínio) do Active Directory.</summary>
    [Required(ErrorMessage = "O domínio (ad) não pode ser vazio.")]
    [MaxLength(256, ErrorMessage = "O domínio (ad) deve ter no máximo 256 caracteres.")]
    public string Ad { get; init; } = string.Empty;
}
