using System;
using System.Collections.Generic;
using System.IO;

namespace AtlusScriptLibrary.FlowScriptLanguage;

/// <summary>
/// Binary details of the original file that its bytecode does not imply. The decompiler writes
/// them as header comment directives, which other tools ignore, and the compiler reads them back.
/// </summary>
public class BinaryLayout
{
    private const string Directive = "@binary";
    private const string NoStringSectionName = "no-string-section";
    private const string MessageScriptVersionName = "msg-version";

    /// <summary>
    /// The original file has no String section at all, not even the reserved empty one.
    /// </summary>
    public bool NoStringSection { get; set; }

    /// <summary>
    /// The embedded MessageScript is an MSG0 file.
    /// </summary>
    public bool MessageScriptVersion0 { get; set; }

    public bool IsEmpty => !NoStringSection && !MessageScriptVersion0;

    public IEnumerable<string> ToDirectives()
    {
        if (NoStringSection)
            yield return $"{Directive} {NoStringSectionName}";

        if (MessageScriptVersion0)
            yield return $"{Directive} {MessageScriptVersionName} 0";
    }

    /// <summary>
    /// Reads the directives from the comment header of a source file. Returns null when it has none.
    /// </summary>
    public static BinaryLayout FromHeader(string source)
    {
        if (string.IsNullOrEmpty(source))
            return null;

        var layout = new BinaryLayout();
        using (var reader = new StringReader(source))
        {
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                line = line.Trim();
                if (line.Length == 0)
                    continue;

                // The directives sit in the comment header, so the first code ends the search.
                if (!line.StartsWith("//"))
                    break;

                var comment = line.Substring(2).Trim();
                if (!comment.StartsWith(Directive, StringComparison.Ordinal))
                    continue;

                var parts = comment.Substring(Directive.Length)
                    .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length == 1 && parts[0] == NoStringSectionName)
                    layout.NoStringSection = true;
                else if (parts.Length == 2 && parts[0] == MessageScriptVersionName && parts[1] == "0")
                    layout.MessageScriptVersion0 = true;
            }
        }

        return layout.IsEmpty ? null : layout;
    }
}
