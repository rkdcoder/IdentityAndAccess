namespace SharedKernel.Primitives
{
    public abstract class DomainEvent
    {
        public DateTimeOffset OccurredOn { get; } = DateTimeOffset.UtcNow;
    }
}