namespace SharedKernel.Abstractions
{
    public interface IIdGenerator
    {
        Guid NewId();
    }

    public sealed class DefaultIdGenerator : IIdGenerator
    {
        public Guid NewId() => Guid.NewGuid();
    }
}