namespace SharedKernel.Guards
{
    public static class Guard
    {
        public static string NotNullOrWhiteSpace(string? value, string paramName)
            => string.IsNullOrWhiteSpace(value)
               ? throw new ArgumentException($"{paramName} cannot be empty.", paramName)
               : value;
    }
}