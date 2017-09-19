using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Antlr4.Runtime;

namespace AtlusScriptLib.MessageScriptLanguage.Parser
{
    public static class MessageScriptParserHelper
    {
        public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( string input )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream );
        }

        public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( TextReader input )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream );
        }

        public static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( Stream input )
        {
            var inputStream = new AntlrInputStream( input );
            return ParseCompilationUnit( inputStream );
        }

        private static MessageScriptParser.CompilationUnitContext ParseCompilationUnit( AntlrInputStream inputStream )
        {
            var lexer = new MessageScriptLexer( inputStream );
            var tokenStream = new CommonTokenStream( lexer );
            var parser = new MessageScriptParser( tokenStream );
            parser.BuildParseTree = true;
            var cst = parser.compilationUnit();

            return cst;
        }
    }
}
