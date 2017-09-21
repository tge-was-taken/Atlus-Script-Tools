using System;
using System.Collections.Generic;
using System.IO;

using Antlr4.Runtime;
using Antlr4.Runtime.Tree;

using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Parser;
using AtlusScriptLib.FlowScriptLanguage.Ast.Nodes;

namespace AtlusScriptLib.FlowScriptLanguage.Ast
{
    /// <summary>
    /// Represents a parser that turns ANTLR's parse tree into an abstract syntax tree (AST).
    /// </summary>
    public class FlowScriptAstParser
    {
        private Logger mLogger;

        public FlowScriptAstParser()
        {
            mLogger = new Logger( nameof( FlowScriptAstParser ) );
        }

        /// <summary>
        /// Adds a parser log listener. Use this if you want to see what went wrong during parsing.
        /// </summary>
        /// <param name="listener">The listener to add.</param>
        public void AddListener( LogListener listener )
        {
            listener.Subscribe( mLogger );
        }

        /// <summary>
        /// Parse the given input source. An exception is thrown on failure.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <returns>The output of the parsing.</returns>
        public FlowScriptCompilationUnit Parse( string input )
        {
            if ( !TryParse( input, out var script ) )
                throw new FlowScriptAstParserFailureException();

            return script;
        }

        /// <summary>
        /// Parse the given input source. An exception is thrown on failure.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <returns>The output of the parsing.</returns>
        public FlowScriptCompilationUnit Parse( TextReader input )
        {
            if ( !TryParse( input, out var script ) )
                throw new FlowScriptAstParserFailureException();

            return script;
        }

        /// <summary>
        /// Parse the given input source. An exception is thrown on failure.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <returns>The output of the parsing.</returns>
        public FlowScriptCompilationUnit Parse( Stream input )
        {
            if ( !TryParse( input, out var script ) )
                throw new FlowScriptAstParserFailureException();

            return script;
        }

        /// <summary>
        /// Attempts to parse the given input source.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <param name="ast">The output of the parsing. Is only guaranteed to be valid if the operation succeeded.</param>
        /// <returns>A boolean value indicating whether the parsing succeeded or not.</returns>
        public bool TryParse( string input, out FlowScriptCompilationUnit ast )
        {
            var cst = FlowScriptParserHelper.ParseCompilationUnit( input );
            return TryParseCompilationUnit( cst, out ast );
        }

        /// <summary>
        /// Attempts to parse the given input source.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <param name="ast">The output of the parsing. Is only guaranteed to be valid if the operation succeeded.</param>
        /// <returns>A boolean value indicating whether the parsing succeeded or not.</returns>
        public bool TryParse( TextReader input, out FlowScriptCompilationUnit ast )
        {
            var cst = FlowScriptParserHelper.ParseCompilationUnit( input, new AntlrErrorListener( mLogger ) );
            return TryParseCompilationUnit( cst, out ast );
        }

        /// <summary>
        /// Attempts to parse the given input source.
        /// </summary>
        /// <param name="input">The input source.</param>
        /// <param name="ast">The output of the parsing. Is only guaranteed to be valid if the operation succeeded.</param>
        /// <returns>A boolean value indicating whether the parsing succeeded or not.</returns>
        public bool TryParse( Stream input, out FlowScriptCompilationUnit ast )
        {
            var cst = FlowScriptParserHelper.ParseCompilationUnit( input, new AntlrErrorListener( mLogger ) );
            return TryParseCompilationUnit( cst, out ast );
        }

        private bool TryParseCompilationUnit( FlowScriptParser.CompilationUnitContext context, out FlowScriptCompilationUnit compilationUnit )
        {
            LogContextInfo( context );

            compilationUnit = CreateAstNode<FlowScriptCompilationUnit>( context );

            // Parse using statements
            if ( TryGet( context, () => context.importStatement(), out var importContexts ) )
            {
                List<FlowScriptImport> imports = null;
                if ( !TryFunc( context, "Failed to parse imports", () => TryParseImports( importContexts, out imports ) ) )
                    return false;

                compilationUnit.Imports = imports;
            }

            // Parse statements
            if ( !TryGet( context, "Expected statement(s)", () => context.statement(), out var statementContexts ) )
                return false;

            List<FlowScriptStatement> statements = null;
            if ( !TryFunc( context, "Failed to parse statement(s)", () => TryParseStatements( statementContexts, out statements ) ) )
                return false;

            compilationUnit.Statements = statements;

            return true;
        }

        //
        // Imports
        //
        private bool TryParseImports( FlowScriptParser.ImportStatementContext[] contexts, out List<FlowScriptImport> imports )
        {
            imports = new List<FlowScriptImport>();

            foreach ( var importContext in contexts )
            {
                FlowScriptImport import = null;
                if ( !TryFunc( importContext, "Failed to parse import statement", () => TryParseImport( importContext, out import ) ) )
                    return false;

                imports.Add( import );
            }

            return true;
        }

        private bool TryParseImport( FlowScriptParser.ImportStatementContext context, out FlowScriptImport import )
        {
            LogContextInfo( context );

            import = null;

            if ( !TryGet( context, "Expected file path", () => context.StringLiteral(), out var filePathNode ) )
                return false;

            if ( !TryGet( context, "Expected file path", () => filePathNode.Symbol.Text, out var filePath ) )
                return false;

            import = CreateAstNode<FlowScriptImport>( context );
            import.CompilationUnitFileName = filePath;

            return true;
        }

        //
        // Statemetns
        //
        private bool TryParseStatements( FlowScriptParser.StatementContext[] contexts, out List<FlowScriptStatement> statements )
        {
            statements = new List<FlowScriptStatement>();

            foreach ( var context in contexts )
            {
                FlowScriptStatement statement = null;
                if ( !TryFunc( context, "Failed to parse statement", () => TryParseStatement( context, out statement ) ) )
                    return false;

                statements.Add( statement );
            }

            return true;
        }

        private bool TryParseStatement( FlowScriptParser.StatementContext context, out FlowScriptStatement statement )
        {
            LogContextInfo( context );

            statement = null;

            // Parse declaration statement
            if ( TryGet( context, () => context.declarationStatement(), out var declarationContext ) )
            {
                FlowScriptDeclaration declaration = null;
                if ( !TryFunc( declarationContext, "Failed to parse declaration", () => TryParseDeclaration( declarationContext, out declaration ) ) )
                    return false;

                statement = declaration;
            }

            return true;
        }

        //
        // Declaration statements
        //
        private bool TryParseDeclaration( FlowScriptParser.DeclarationStatementContext context, out FlowScriptDeclaration declaration )
        {
            LogContextInfo( context );

            declaration = null;

            // Parse function declaration statement
            if ( TryGet( context, () => context.functionDeclarationStatement(), out var functionDeclarationContext))
            {

            }
            else if ( TryGet( context, () => context.procedureDeclarationStatement(), out var procedureDeclarationContext))
            {
                FlowScriptProcedureDeclaration procedureDeclaration = null;
                if ( !TryFunc( procedureDeclarationContext, "Failed to parse procedure declaration", () => TryParseProcedureDeclaration( procedureDeclarationContext, out procedureDeclaration ) ) )
                    return false;

                declaration = procedureDeclaration;
            }

            return true;
        }

        private bool TryParseProcedureDeclaration( FlowScriptParser.ProcedureDeclarationStatementContext context, out FlowScriptProcedureDeclaration procedureDeclaration )
        {
            LogContextInfo( context );

            procedureDeclaration = CreateAstNode<FlowScriptProcedureDeclaration>( context );

            // Parse return type
            if ( !TryGet( context, "Expected procedure return type", () => context.TypeIdentifier(), out var typeIdentifierNode ) )
                return false;

            FlowScriptTypeIdentifier typeIdentifier = null;
            if ( !TryFunc( typeIdentifierNode, "Failed to parse procedure return type identifier", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                return false;

            procedureDeclaration.ReturnType = typeIdentifier;

            // Parse identifier
            if ( !TryGet( context, "Expected procedure identifier", () => context.Identifier(), out var identifierNode ) )
                return false;

            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse procedure identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                return false;

            procedureDeclaration.Identifier = identifier;

            // Parse parameter list
            if ( !TryGet( context, "Expected procedure parameter list", () => context.parameterList(), out var parameterListContext ) )
                return false;

            List<FlowScriptParameter> parameters = null;
            if ( !TryFunc( parameterListContext, "Failed to parse procedure parameter list", () => TryParseParameterList( parameterListContext, out parameters ) ) )
                return false;

            procedureDeclaration.Parameters = parameters;

            return true;
        }

        //
        // Parameter list
        //
        private bool TryParseParameterList( FlowScriptParser.ParameterListContext context, out List<FlowScriptParameter> parameters )
        {
            LogContextInfo( context );

            parameters = new List<FlowScriptParameter>();

            // Parse parameter list
            if ( !TryGet( context, "Expected parameter list", () => context.parameter(), out var parameterContexts ) )
                return false;

            foreach ( var parameterContext in parameterContexts )
            {
                FlowScriptParameter parameter = null;
                if ( !TryFunc( parameterContext, "Failed to parse parameter", () => TryParseParameter( parameterContext, out parameter ) ) )
                    return false;

                parameters.Add( parameter );
            }

            return true;
        }

        private bool TryParseParameter( FlowScriptParser.ParameterContext context, out FlowScriptParameter parameter )
        {
            LogContextInfo( context );

            parameter = CreateAstNode<FlowScriptParameter>( context );

            // Parse type identifier
            if ( !TryGet( context, "Expected parameter type", () => context.TypeIdentifier(), out var typeIdentifierNode ) )
                return false;

            FlowScriptTypeIdentifier typeIdentifier = null;
            if ( !TryFunc( typeIdentifierNode, "Failed to parse parameter type", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                return false;

            parameter.TypeIdentifier = typeIdentifier;

            // Parse identifier
            if ( !TryGet( context, "Expected parameter identifier", () => context.Identifier(), out var identifierNode ) )
                return false;

            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse parameter identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                return false;

            parameter.Identifier = identifier;


            return true;
        }

        //
        // Identifiers
        //
        private bool TryParseTypeIdentifier( ITerminalNode node, out FlowScriptTypeIdentifier identifier )
        {
            identifier = CreateAstNode<FlowScriptTypeIdentifier>( node );

            if ( !Enum.TryParse<FlowScriptPrimitiveType>( node.Symbol.Text, true, out var primitiveType ) )
            {
                LogError( node.Symbol, $"Unknown primitive type: {node.Symbol.Text}" );
                return false;
            }

            identifier.PrimitiveType = primitiveType;

            return true;
        }

        private bool TryParseIdentifier( ITerminalNode identifierNode, out FlowScriptIdentifier identifier )
        {
            identifier = CreateAstNode<FlowScriptIdentifier>( identifierNode );
            identifier.Text = identifierNode.Symbol.Text;

            return true;
        }

        private T CreateAstNode<T>( ParserRuleContext context ) where T : FlowScriptAstNode, new()
        {
            T instance = new T();
            instance.SourceInfo = ParseSourceInfo( context.Start );

            return instance;
        }

        private T CreateAstNode<T>( ITerminalNode node ) where T : FlowScriptAstNode, new()
        {
            T instance = new T();
            instance.SourceInfo = ParseSourceInfo( node.Symbol );

            return instance;
        }

        private FlowScriptAstSourceInfo ParseSourceInfo( IToken token )
        {
            return new FlowScriptAstSourceInfo( token.Line, token.Column, token.TokenSource.SourceName );
        }

        //
        // Predicates
        //
        private bool TryFunc( ParserRuleContext context, string errorText, Func<bool> func ) 
        {
            if ( !func() )
            {
                LogError( context, errorText );
                return false;
            }

            return true;
        }

        private bool TryFunc( ITerminalNode node, string errorText, Func<bool> func )
        {
            if ( !func() )
            {
                LogError( node.Symbol, errorText );
                return false;
            }

            return true;
        }

        private bool TryAction( ITerminalNode node, string errorText, Action action )
        {
            if ( !TryAction( action ) )
            {
                LogError( node.Symbol, errorText );
                return false;
            }

            return true;
        }

        private bool TryAction( ParserRuleContext context, string errorText, Action action )
        {
            if ( !TryAction(action))
            {
                LogError( context, errorText );
                return false;
            }

            return true;
        }

        private bool TryAction( Action action )
        {
            try
            {
                action();
            }
            catch ( Exception e )
            {
                return false;
            }

            return true;
        }

        private bool TryGet<T>( ParserRuleContext context, string errorText, Func<T> getFunc, out T value )
        {
            bool success = TryGet( context, getFunc, out value );

            if ( !success )
                LogError( context, errorText );

            return success;
        }

        private bool TryGet<T>( ParserRuleContext context, Func<T> getFunc, out T value )
        {
            try
            {
                value = getFunc();
            }
            catch ( Exception e )
            {
                value = default( T );
                return false;
            }

            if ( value == null )
                return false;

            return true;
        }

        private bool TryCast<T>( object obj, out T value ) where T : class
        {
            value = obj as T;
            return value != null;
        }

        //
        // Logging
        //
        private void LogContextInfo( ParserRuleContext context )
        {
            mLogger.Info( $"Parsing parser rule node {FlowScriptParser.ruleNames[context.RuleIndex]} ({context.Start.Line}:{context.Start.Column})" );
        }

        private void LogError( ParserRuleContext context, string str )
        {
            mLogger.Error( $"{str} ({context.Start.Line}:{context.Start.Column})" );
        }

        private void LogError( IToken token, string str )
        {
            mLogger.Error( $"{str} ({token.Line}:{token.Column})" );
        }

        private void LogWarning( ParserRuleContext context, string str )
        {
            mLogger.Warning( $"{str} ({context.Start.Line}:{context.Start.Column})" );
        }

        /// <summary>
        /// Antlr error listener for catching syntax errors while parsing.
        /// </summary>
        private class AntlrErrorListener : IAntlrErrorListener<IToken>
        {
            private Logger mLogger;

            public AntlrErrorListener( Logger logger )
            {
                mLogger = logger;
            }

            public void SyntaxError( IRecognizer recognizer, IToken offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e )
            {
                mLogger.Error( $"Syntax error: {msg} ({offendingSymbol.Line}:{offendingSymbol.Column})" );
            }
        }
    }
}
