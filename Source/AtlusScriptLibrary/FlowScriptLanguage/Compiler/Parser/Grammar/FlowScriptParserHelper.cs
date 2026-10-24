using Antlr4.Runtime;
using Antlr4.Runtime.Atn;
using Antlr4.Runtime.Misc;
using System.IO;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser.Grammar;

public static class FlowScriptParserHelper
{
    public static FlowScriptParser.CompilationUnitContext ParseCompilationUnit(string input, IAntlrErrorListener<IToken> errorListener = null)
    {
        var inputStream = new AntlrInputStream(input);
        return ParseCompilationUnit(inputStream, errorListener);
    }

    public static FlowScriptParser.CompilationUnitContext ParseCompilationUnit(TextReader input, IAntlrErrorListener<IToken> errorListener = null)
    {
        var inputStream = new AntlrInputStream(input);
        return ParseCompilationUnit(inputStream, errorListener);
    }

    public static FlowScriptParser.CompilationUnitContext ParseCompilationUnit(Stream input, IAntlrErrorListener<IToken> errorListener = null)
    {
        var inputStream = new AntlrInputStream(input);
        return ParseCompilationUnit(inputStream, errorListener);
    }

    private static FlowScriptParser.CompilationUnitContext ParseCompilationUnit(AntlrInputStream inputStream, IAntlrErrorListener<IToken> errorListener = null)
    {
        // The cheap prediction mode parses a large script tens of times faster but can reject
        // input that needs the full one, so a rejection is retried rather than reported.
        if (TryParseFast(inputStream, out var cst))
            return cst;

        inputStream.Seek(0);
        var parser = CreateParser(inputStream);
        parser.ErrorHandler = new DefaultErrorStrategy();

        if (errorListener != null)
        {
            parser.RemoveErrorListeners();
            parser.AddErrorListener(errorListener);
        }

        return parser.compilationUnit();
    }

    private static bool TryParseFast(AntlrInputStream inputStream, out FlowScriptParser.CompilationUnitContext cst)
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

    private static FlowScriptParser CreateParser(AntlrInputStream inputStream, bool quiet = false)
    {
        var lexer = new FlowScriptLexer(inputStream);
        var parser = new FlowScriptParser(new CommonTokenStream(lexer));
        parser.BuildParseTree = true;

        if (quiet)
        {
            lexer.RemoveErrorListeners();
            parser.RemoveErrorListeners();
        }

        return parser;
    }
}
