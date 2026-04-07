namespace SharedKernel.Abstractions
{
    public readonly struct Maybe<T>
    {
        public bool HasValue { get; }
        public T? Value { get; }
        private Maybe(T value) { HasValue = true; Value = value; }
        public static Maybe<T> None => default;
        public static Maybe<T> Some(T value) => new(value);
    }
}