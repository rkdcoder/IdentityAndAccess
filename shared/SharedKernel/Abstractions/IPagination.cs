namespace SharedKernel.Abstractions
{
    public interface IPagination
    {
        int Page { get; }
        int PageSize { get; }
    }
}