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

        mHeaderWriter = headerWriter;
    }

    public void Decompile(MessageScript script)
    {
        WriteHeaderComment("Decompiled by Atlus Script Tools (2017-2021) © TGE");

        for (var i = 0; i < script.Dialogs.Count; i++)
        {
            var message = script.Dialogs[i];
            WriteHeaderLine($"const int {FormatIdentifier(message.Name).PadRight(32)} = {i};");
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
                        WriteCloseTag();
                    }
                    break;
            }
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

        WriteTag("sel", FormatIdentifier(message.Name), pattern);
        mWriter.WriteLine();

        foreach (var line in message.Options)
        {
            Decompile(line);
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

                    if (!string.IsNullOrWhiteSpace(function.Name))
                    {
                        WriteOpenTag(FormatIdentifier(function.Name));

                        for (var i = 0; i < function.Parameters.Count; i++)
                        {
                            var argument = function.Parameters[i];
                            WriteTagArgument(token.Arguments[i].ToString());
                        }

                        WriteCloseTag();
                        return;
                    }
                }
            }
        }

        if (token.Arguments.Count == 0)
        {
            WriteTag("f", token.FunctionTableIndex.ToString(), token.FunctionIndex.ToString());
        }
        else
        {
            WriteOpenTag("f");
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
        mWriter.Write(token.Value);
    }

    public void Decompile(CodePointToken token)
    {
        WriteTag($"x 0x{token.HighSurrogate:X2} 0x{token.LowSurrogate:X2}");
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
