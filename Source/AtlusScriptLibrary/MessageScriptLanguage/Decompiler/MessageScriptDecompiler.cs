using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Text;
using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace AtlusScriptLibrary.MessageScriptLanguage.Decompiler;

public sealed class MessageScriptDecompiler : IDisposable
{
    private static Regex sIdentifierRegex = new Regex("^[a-zA-Z_][a-zA-Z0-9_]*$");

    private readonly TextWriter mWriter;
    private readonly TextWriter mHeaderWriter;

    public Library Library { get; set; }

    public bool OmitUnusedFunctions { get; set; } = true;

    public MessageScriptDecompiler(TextWriter writer, TextWriter headerWriter = null)
    {
        mWriter = writer;

        if (headerWriter == null && writer is FileTextWriter fileTextWriter)
        {
            headerWriter = new FileTextWriter(fileTextWriter.Path + ".h");
        }
        if (headerWriter == null && writer is StringWriter stringWriter)
        {
            headerWriter = new StringWriter();
        }

        mHeaderWriter = headerWriter;
    }

    public void Decompile(MessageScript script)
    {
        WriteHeaderComment("Decompiled by Atlus Script Tools");

        var identifiers = script.GetDialogIdentifiers();

        for (var i = 0; i < script.Dialogs.Count; i++)
        {
            var message = script.Dialogs[i];
            WriteHeaderLine($"const int {FormatIdentifier(identifiers[i]).PadRight(32)} = {i};");
            Decompile(message);
            mWriter.WriteLine();
        }
    }

    public void Decompile(IDialog message)
    {
        switch (message.Kind)
        {
            case DialogKind.Message:
                Decompile((MessageDialog)message);
                break;
            case DialogKind.Selection:
                Decompile((SelectionDialog)message);
                break;

            default:
                throw new NotImplementedException(message.Kind.ToString());
        }
    }

    public void Decompile(MessageDialog message)
    {
        if (message.Speaker != null)
        {
            switch (message.Speaker.Kind)
            {
                case SpeakerKind.Named:
                    {
                        WriteOpenTag("msg");
                        WriteTagArgument(FormatIdentifier(message.Name));
                        {
                            mWriter.Write(" ");

                            var speaker = (NamedSpeaker)message.Speaker;
                            if (speaker.Name != null)
                            {
                                WriteOpenTag();
                                Decompile(speaker.Name, false);
                                WriteCloseTag();
                            }
                        }
                        if (message.OmitTrailingTerminator)
                            WriteTagArgument("noterm");
                        WriteCloseTag();
                    }
                    break;

                case SpeakerKind.Variable:
                    {
                        WriteOpenTag("msg");
                        WriteTagArgument(FormatIdentifier(message.Name));
                        {
                            mWriter.Write(" ");
                            WriteOpenTag();
                            mWriter.Write(((VariableSpeaker)message.Speaker).Index.ToString());
                            WriteCloseTag();
                        }
                        if (message.OmitTrailingTerminator)
                            WriteTagArgument("noterm");
                        WriteCloseTag();
                    }
                    break;
            }
        }
        else if (message.OmitTrailingTerminator)
        {
            WriteTag("msg", FormatIdentifier(message.Name), "noterm");
        }
        else
        {
            WriteTag("msg", FormatIdentifier(message.Name));
        }

        mWriter.WriteLine();

        foreach (var line in message.Pages)
        {
            Decompile(line);
            mWriter.WriteLine();
        }
    }

    public void Decompile(SelectionDialog message)
    {
        var pattern = "";
        if (message.Pattern == SelectionDialogPattern.Top)
            pattern = "top";
        else if (message.Pattern == SelectionDialogPattern.Bottom)
            pattern = "bottom";
        else
            pattern = ((int)message.Pattern).ToString();

        if (message.OmitTrailingTerminator)
            WriteTag("sel", FormatIdentifier(message.Name), pattern, "noterm");
        else
            WriteTag("sel", FormatIdentifier(message.Name), pattern);

        mWriter.WriteLine();

        foreach (var option in message.Options)
        {
            Decompile(option);
            mWriter.WriteLine();
        }
    }

    public void Decompile(TokenText line, bool emitLineEndTag = true)
    {
        foreach (var token in line.Tokens)
        {
            Decompile(token);
        }

        if (emitLineEndTag)
            WriteTag("e");
    }

    public void Decompile(IToken token)
    {
        switch (token.Kind)
        {
            case TokenKind.String:
                Decompile((StringToken)token);
                break;
            case TokenKind.Function:
                Decompile((FunctionToken)token);
                break;
            case TokenKind.CodePoint:
                Decompile((CodePointToken)token);
                break;
            case TokenKind.NewLine:
                Decompile((NewLineToken)token);
                break;

            default:
                throw new NotImplementedException(token.Kind.ToString());
        }
    }

    public void Decompile(FunctionToken token)
    {
        if (Library != null)
        {
            var library = Library.MessageScriptLibraries.FirstOrDefault(x => x.Index == token.FunctionTableIndex);
            if (library != null)
            {
                var function = library.Functions.FirstOrDefault(x => x.Index == token.FunctionIndex);
                if (function != null)
                {
                    if (function.Semantic == MessageScriptLibraryFunctionSemantic.Unused && OmitUnusedFunctions)
                        return;

                    // Writing the name would drop or invent arguments when the library disagrees with
                    // the token, so keep the raw form and stay reversible.
                    if (!string.IsNullOrWhiteSpace(function.Name) &&
                        function.Parameters.Count == token.Arguments.Count)
                    {
                        WriteOpenTag(FormatIdentifier(function.Name));

                        foreach (var argument in token.Arguments)
                            WriteTagArgument(argument.ToString());

                        WriteCloseTag();
                        return;
                    }
                }
            }
        }
        var tagHeader = "f";
        if (token.Arguments.Count == 0)
        {
            WriteTag(tagHeader, token.FunctionTableIndex.ToString(), token.FunctionIndex.ToString());
        }
        else
        {
            WriteOpenTag(tagHeader);
            WriteTagArgument(token.FunctionTableIndex.ToString());
            WriteTagArgument(token.FunctionIndex.ToString());

            foreach (var tokenArgument in token.Arguments)
            {
                WriteTagArgument(tokenArgument.ToString());
            }

            WriteCloseTag();
        }
    }

    public void Decompile(StringToken token)
    {
        // The compiler drops the newlines of the source file's own layout, so a control character in
        // the text buffer has to be written as a code point to survive recompilation.
        var start = 0;
        for (var i = 0; i < token.Value.Length; i++)
        {
            if (token.Value[i] >= ' ')
                continue;

            WriteText(token.Value.Substring(start, i - start));
            WriteTag($"x 0x{(int)token.Value[i]:X2}");
            start = i + 1;
        }

        WriteText(token.Value.Substring(start));
    }

    private void WriteText(string text)
    {
        mWriter.Write(text.Replace("[", "\\[").Replace("]", "\\]"));
    }

    public void Decompile(CodePointToken token)
    {
        WriteTag($"x {string.Join(" ", token.Bytes.Select(x => $"0x{x:X2}"))}");
    }

    public void Decompile(NewLineToken token)
    {
        WriteTag("n");
    }

    public void Dispose()
    {
        mWriter.Dispose();
        mHeaderWriter?.Dispose();
    }

    private void WriteOpenTag()
    {
        mWriter.Write("[");
    }

    private void WriteOpenTag(string tag)
    {
        mWriter.Write($"[{tag}");
    }

    private void WriteTagArgument(string argument)
    {
        mWriter.Write(" ");
        mWriter.Write(argument);
    }

    private void WriteCloseTag()
    {
        mWriter.Write("]");
    }

    private void WriteTag(string tag, params string[] arguments)
    {
        WriteOpenTag(tag);

        if (arguments.Length != 0)
        {
            foreach (var argument in arguments)
            {
                WriteTagArgument(argument);
            }
        }

        WriteCloseTag();
    }

    private string FormatIdentifier(string text)
    {
        if (!sIdentifierRegex.IsMatch(text))
            return "``" + text + "``";
        else
            return text;
    }

    private void WriteComment(string text)
    {
        // Disabled temporarily
    }

    private void WriteHeaderComment(string text)
    {
        mHeaderWriter.WriteLine($"// {text}");
    }

    private void WriteHeaderLine(string text)
    {
        mHeaderWriter.WriteLine(text);
    }
}
