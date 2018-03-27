using System.IO;
using Antlr4.Runtime;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser;

namespace AtlusScriptLibrary.MessageScriptLanguage.Compiler.Parser
{
    public static class MessageScriptParserHelper
    {
        public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( string input, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream, errorListener );
        }

        public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( TextReader input, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream, errorListener );
        }

        public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( Stream input, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream, errorListener );
        }

        private static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( AntlrInputStream inputStream, IAntlrErrorListener<Antlr4.Runtime.IToken> errorListener = null )
        {
            var lexer = new MessageScriptLexer( inputStream );
            var tokenStream = new CommonTokenStream( lexer );

            // parser
            var parser = new MessageScriptParser( tokenStream );
            parser.BuildParseTree = true;
            //parser.ErrorHandler = new BailErrorStrategy();

            if ( errorListener != null )
            {
                parser.RemoveErrorListeners();
                parser.AddErrorListener( errorListener );
            }

            var cst = parser.compilationUnit();

            return cst;
        }
    }
}
