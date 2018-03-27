using System.IO;
using Antlr4.Runtime;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser.Grammar
{
    public static class FlowScriptParserHelper
    {
        public static FlowScriptParser.CompilationUnitContext ParseCompilationUnit( string input, IAntlrErrorListener<IToken> errorListener = null )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream, errorListener );
        }

        public static FlowScriptParser.CompilationUnitContext ParseCompilationUnit( TextReader input, IAntlrErrorListener<IToken> errorListener = null )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream, errorListener );
        }

        public static FlowScriptParser.CompilationUnitContext ParseCompilationUnit( Stream input, IAntlrErrorListener<IToken> errorListener = null )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream, errorListener );
        }

        private static FlowScriptParser.CompilationUnitContext ParseCompilationUnit( AntlrInputStream inputStream, IAntlrErrorListener<IToken> errorListener = null )
        {
            var lexer = new FlowScriptLexer( inputStream );
            var tokenStream = new CommonTokenStream( lexer );

            // parser
            var parser = new FlowScriptParser( tokenStream );
            parser.BuildParseTree = true;
            //parser.ErrorHandler = new BailErrorStrategy();
            parser.ErrorHandler = new DefaultErrorStrategy();

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
