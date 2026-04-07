namespace SharedKernel.Abstractions
{
    public readonly struct Result<T>
    {
        public bool Success { get; }
        public string Message { get; }
        public T? Data { get; }

        private Result(bool success, string message, T? data)
            => (Success, Message, Data) = (success, message, data);

        public static Result<T> Ok(T data, string message = "OK") => new(true, message, data);
        public static Result<T> Fail(string message) => new(false, message, default);
    }
}