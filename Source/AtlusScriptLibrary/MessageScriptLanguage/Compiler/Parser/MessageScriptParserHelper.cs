using Antlr4.Runtime;
using Antlr4.Runtime.Atn;
using Antlr4.Runtime.Misc;
using System.IO;

namespace AtlusScriptLibrary.MessageScriptLanguage.Compiler.Parser;

public static class MessageScriptParserHelper
{
    public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit(string input, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null)
    {
        var inputStream = new AntlrInputStream(input);
        return ParseCompilationUnit(inputStream, errorListener);
    }

    public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit(TextReader input, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null)
    {
        var inputStream = new AntlrInputStream(input);
        return ParseCompilationUnit(inputStream, errorListener);
    }

    public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit(Stream input, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null)
    {
        var inputStream = new AntlrInputStream(input);
        return ParseCompilationUnit(inputStream, errorListener);
    }

    private static MessageScriptParser.CompilationUnitContext ParseCompilationUnit(AntlrInputStream inputStream, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null)
    {
        // The cheap prediction mode is several times faster but can reject input that needs the
        // full one, so a rejection is retried rather than reported.
        if (TryParseFast(inputStream, out var cst))
            return cst;

        inputStream.Seek(0);
        var parser = CreateParser(inputStream);

        if (errorListener != null)
        {
            parser.RemoveErrorListeners();
            parser.AddErrorListener(errorListener);
        }

        return parser.compilationUnit();
    }

    private static bool TryParseFast(AntlrInputStream inputStream, out MessageScriptParser.CompilationUnitContext cst)
    {
        var parser = CreateParser(inputStream, quiet: true);
        parser.Interpreter.PredictionMode = PredictionMode.Sll;
        parser.ErrorHandler = new BailErrorStrategy();

        try
        {
            cst = parser.compilationUnit();
            return true;
        }
        catch (ParseCanceledException)
        {
            cst = null;
            return false;
        }
    }

    private static MessageScriptParser CreateParser(AntlrInputStream inputStream, bool quiet = false)
    {
        var lexer = new MessageScriptLexer(inputStream);
        var parser = new MessageScriptParser(new CommonTokenStream(lexer));
        parser.BuildParseTree = true;

        if (quiet)
        {
            lexer.RemoveErrorListeners();
            parser.RemoveErrorListeners();
        }

        return parser;
    }
}
