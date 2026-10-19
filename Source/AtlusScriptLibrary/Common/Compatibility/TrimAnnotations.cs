#if NETSTANDARD2_0
// The trimmer and AOT compiler recognise these by name, so netstandard2.0 can carry its
// own copies and keep one set of annotations across both target frameworks.
namespace System.Diagnostics.CodeAnalysis;

[Flags]
internal enum DynamicallyAccessedMemberTypes
{
    None = 0,
    PublicParameterlessConstructor = 1,
    PublicConstructors = 3,
    NonPublicConstructors = 4,
    PublicMethods = 8,
    NonPublicMethods = 16,
    PublicFields = 32,
    NonPublicFields = 64,
    PublicNestedTypes = 128,
    NonPublicNestedTypes = 256,
    PublicProperties = 512,
    NonPublicProperties = 1024,
    PublicEvents = 2048,
    NonPublicEvents = 4096,
    Interfaces = 8192,
    All = ~None
}

[AttributeUsage(
    AttributeTargets.Field | AttributeTargets.ReturnValue | AttributeTargets.GenericParameter |
    AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.Method,
    Inherited = false)]
internal sealed class DynamicallyAccessedMembersAttribute : Attribute
{
    public DynamicallyAccessedMembersAttribute(DynamicallyAccessedMemberTypes memberTypes)
        => MemberTypes = memberTypes;

    public DynamicallyAccessedMemberTypes MemberTypes { get; }
}

[AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
internal sealed class UnconditionalSuppressMessageAttribute : Attribute
{
    public UnconditionalSuppressMessageAttribute(string category, string checkId)
    {
        Category = category;
        CheckId = checkId;
    }

    public string Category { get; }
    public string CheckId { get; }
    public string Scope { get; set; }
    public string Target { get; set; }
    public string MessageId { get; set; }
    public string Justification { get; set; }
}
#endif
