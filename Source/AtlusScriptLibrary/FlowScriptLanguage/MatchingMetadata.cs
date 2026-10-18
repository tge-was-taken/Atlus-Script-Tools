namespace AtlusScriptLibrary.FlowScriptLanguage;

/// <summary>
/// Names of the file-scope constants the decompiler writes to record binary details that the
/// bytecode does not imply, and the compiler reads back when matching. They compile to nothing,
/// so other tools can ignore them.
/// </summary>
public static class MatchingMetadata
{
    /// <summary>
    /// The original file has no String section at all, not even the reserved empty one.
    /// </summary>
    public const string NoStringSection = "__no_string_section";

    /// <summary>
    /// The embedded MessageScript is an MSG0 file.
    /// </summary>
    public const string MessageScriptVersion0 = "__msg_version_0";
}
