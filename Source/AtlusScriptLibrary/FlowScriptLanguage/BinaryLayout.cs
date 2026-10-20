using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage;

/// <summary>
/// Binary details of the original file that its bytecode does not imply. The decompiler writes
/// them as pragmas and the compiler reads them back.
/// </summary>
public class BinaryLayout
{
    public const string OmitEmptyStringSectionOption = "omit-empty-string-section";
    public const string MessageScriptVersionOption = "msg-version";

    /// <summary>
    /// The original file leaves out the String section rather than writing the reserved empty one.
    /// </summary>
    public bool OmitEmptyStringSection { get; set; }

    /// <summary>
    /// The embedded MessageScript is an MSG0 file.
    /// </summary>
    public bool MessageScriptVersion0 { get; set; }

    /// <summary>
    /// Format version of the original file, for the reader. The output format comes from the
    /// command line, so this is not read back.
    /// </summary>
    public FormatVersion? Version { get; set; }

    /// <summary>
    /// Format version of the original embedded MessageScript, for the reader.
    /// </summary>
    public MessageScriptLanguage.FormatVersion? MessageScriptVersion { get; set; }

    public bool IsEmpty => !OmitEmptyStringSection && !MessageScriptVersion0 && Version == null;

    /// <summary>
    /// The options as pragmas, for the writer.
    /// </summary>
    public IEnumerable<string> ToStatements()
    {
        if (OmitEmptyStringSection)
            yield return $"pragma(\"{OmitEmptyStringSectionOption}\");";

        if (MessageScriptVersion0)
            yield return $"pragma(\"{MessageScriptVersionOption}\", 0);";
    }

    /// <summary>
    /// Applies one option. Returns false when the name or its value is not known.
    /// </summary>
    public bool TrySetOption(string name, long? value)
    {
        switch (name)
        {
            case OmitEmptyStringSectionOption when value == null:
                OmitEmptyStringSection = true;
                return true;

            case MessageScriptVersionOption when value == 0:
                MessageScriptVersion0 = true;
                return true;

            default:
                return false;
        }
    }

    /// <summary>
    /// One line naming the versions the original file was read as, or null when unknown.
    /// </summary>
    public string DescribeVersions()
    {
        if (Version == null)
            return null;

        var description = $"Original binary: FlowScript {Version}";
        if (MessageScriptVersion != null)
        {
            description += $", embedded MessageScript {MessageScriptVersion}";

            // The magic says MSG0 while the layout is still read as the library's version.
            if (MessageScriptVersion0)
                description += " (MSG0)";
        }

        return description;
    }
}
