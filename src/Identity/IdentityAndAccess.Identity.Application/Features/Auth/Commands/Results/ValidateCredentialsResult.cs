namespace IdentityAndAccess.Identity.Application.Features.Auth.Commands.Results
{
    public sealed class ValidateCredentialsResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;

        public object? UserInfos { get; init; }

        public static ValidateCredentialsResult Ok(string message, object userInfos)
            => new() { Success = true, Message = message, UserInfos = userInfos };

        public static ValidateCredentialsResult Fail(string message)
            => new() { Success = false, Message = message, UserInfos = null };
    }
}