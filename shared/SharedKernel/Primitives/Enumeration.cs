namespace SharedKernel.Primitives
{
    public abstract class Enumeration : IComparable
    {
        public int Id { get; }
        public string Name { get; }

        protected Enumeration(int id, string name) { Id = id; Name = name; }
        public int CompareTo(object? other) => Id.CompareTo(((Enumeration)other!).Id);
        public override string ToString() => Name;
    }
}