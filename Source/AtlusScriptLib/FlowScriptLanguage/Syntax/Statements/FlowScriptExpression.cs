using System.Collections.Generic;
using Antlr4.Runtime;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser.Grammar;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Processing;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptExpression : FlowScriptStatement
    {
        public FlowScriptValueType ExpressionValueType { get; set; }

        protected FlowScriptExpression( FlowScriptValueType type )
        {
            ExpressionValueType = type;
        }

        public static FlowScriptExpression FromText( string source )
        {
            var lexer = new FlowScriptLexer( new AntlrInputStream( source ) );
            var tokenStream = new CommonTokenStream( lexer );

            // parse expression
            var parser = new FlowScriptParser( tokenStream );
            parser.BuildParseTree = true;
            var expressionParseTree = parser.expression();

            // parse ast nodes
            var compilationUnitParser = new FlowScriptCompilationUnitParser();
            compilationUnitParser.TryParseExpression( expressionParseTree, out var expression );

            // resolve types
            var typeResolver = new FlowScriptTypeResolver();
            typeResolver.TryResolveTypesInExpression( expression );

            return expression;
        }
    }

    public abstract class FlowScriptCastExpression : FlowScriptExpression
    {
        protected FlowScriptCastExpression( FlowScriptValueType type ) : base( type )
        {
        }
    }
}