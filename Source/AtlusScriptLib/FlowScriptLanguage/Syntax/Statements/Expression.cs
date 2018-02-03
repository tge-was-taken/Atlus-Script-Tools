using Antlr4.Runtime;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser.Grammar;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Processing;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class Expression : Statement
    {
        public ValueKind ExpressionValueKind { get; set; }

        protected Expression( ValueKind kind )
        {
            ExpressionValueKind = kind;
        }

        public static Expression FromText( string source )
        {
            var lexer = new FlowScriptLexer( new AntlrInputStream( source ) );
            var tokenStream = new CommonTokenStream( lexer );

            // parse expression
            var parser = new FlowScriptParser( tokenStream );
            parser.BuildParseTree = true;
            var expressionParseTree = parser.expression();

            // parse ast nodes
            var compilationUnitParser = new CompilationUnitParser();
            compilationUnitParser.TryParseExpression( expressionParseTree, out var expression );

            // resolve types
            var typeResolver = new TypeResolver();
            typeResolver.TryResolveTypesInExpression( expression );

            return expression;
        }
    }

    public abstract class CastExpression : Expression
    {
        protected CastExpression( ValueKind kind ) : base( kind )
        {
        }
    }
}