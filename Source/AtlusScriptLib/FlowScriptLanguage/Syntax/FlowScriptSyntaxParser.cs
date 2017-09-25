using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Antlr4.Runtime;
using Antlr4.Runtime.Tree;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Parser;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    /// <summary>
    /// Represents a parser that turns ANTLR's parse tree into an abstract syntax tree (AST).
    /// </summary>
    public class FlowScriptSyntaxParser
    {
        private Logger mLogger;

        public FlowScriptSyntaxParser()
        {
            mLogger = new Logger( nameof( FlowScriptSyntaxParser ) );
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
                throw new FlowScriptSyntaxParserFailureException();

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
                throw new FlowScriptSyntaxParserFailureException();

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
                throw new FlowScriptSyntaxParserFailureException();

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

        //
        // Parsing
        //
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
        private bool TryParseImports( FlowScriptParser.ImportStatementContext[] contexts, out System.Collections.Generic.List<FlowScriptImport> imports )
        {
            imports = new System.Collections.Generic.List<FlowScriptImport>();

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
        // Statements
        //
        private bool TryParseStatements( FlowScriptParser.StatementContext[] contexts, out System.Collections.Generic.List<FlowScriptStatement> statements )
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
            else if ( TryGet( context, () => context.expression(), out var expressionContext ))
            {
                FlowScriptExpression expression = null;
                if ( !TryFunc( expressionContext, "Failed to parse expression", () => TryParseExpression( expressionContext, out expression ) ) )
                    return false;

                statement = expression;
            }
            else
            {
                LogError( context, "Expected statement" );
            }

            return true;
        }

        private bool TryParseCompoundStatement( FlowScriptParser.CompoundStatementContext context, out FlowScriptCompoundStatement body )
        {
            LogContextInfo( context );

            body = CreateAstNode<FlowScriptCompoundStatement>( context );

            if ( !TryGet( context, "Expected statement(s)", () => context.statement(), out var statementContexts ) )
                return false;

            List<FlowScriptStatement> statements = null;
            if ( !TryFunc( context, "Failed to parse statement(s)", () => TryParseStatements( statementContexts, out statements ) ) )
                return false;

            body.Statements.AddRange( statements );

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
                FlowScriptFunctionDeclaration functionDeclaration = null;
                if ( !TryFunc( functionDeclarationContext, "Failed to parse function declaration", () => TryParseFunctionDeclaration( functionDeclarationContext, out functionDeclaration ) ) )
                    return false;

                declaration = functionDeclaration;
            }
            else if ( TryGet( context, () => context.procedureDeclarationStatement(), out var procedureDeclarationContext))
            {
                FlowScriptProcedureDeclaration procedureDeclaration = null;
                if ( !TryFunc( procedureDeclarationContext, "Failed to parse procedure declaration", () => TryParseProcedureDeclaration( procedureDeclarationContext, out procedureDeclaration ) ) )
                    return false;

                declaration = procedureDeclaration;
            }
            else if ( TryGet( context, () => context.variableDeclarationStatement(), out var variableDeclarationContext))
            {
                FlowScriptVariableDeclaration variableDeclaration = null;
                if ( !TryFunc( variableDeclarationContext, "Failed to parse variable declaration", () => TryParseVariableDeclaration( variableDeclarationContext, out variableDeclaration ) ) )
                    return false;

                declaration = variableDeclaration;
            }
            else
            {
                LogError( context, "Expected function, procedure or variable declaration" );
                return false;
            }

            return true;
        }

        private bool TryParseFunctionDeclaration( FlowScriptParser.FunctionDeclarationStatementContext context, out FlowScriptFunctionDeclaration functionDeclaration )
        {
            LogContextInfo( context );

            functionDeclaration = CreateAstNode<FlowScriptFunctionDeclaration>( context );

            // Parse return type
            {
                if ( !TryGet( context, "Expected function return type", () => context.TypeIdentifier(), out var typeIdentifierNode ) )
                    return false;

                FlowScriptTypeIdentifier typeIdentifier = null;
                if ( !TryFunc( typeIdentifierNode, "Failed to parse function return type identifier", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                    return false;

                functionDeclaration.ReturnType = typeIdentifier;
            }

            // Parse index
            {
                if ( !TryGet( context, "Expected function index", () => context.IntLiteral(), out var indexNode ) )
                    return false;

                FlowScriptIntLiteral indexIntLiteral = null;
                if ( !TryFunc( indexNode, "Failed to parse function index", () => TryParseIntLiteral( indexNode, out indexIntLiteral ) ) )
                    return false;

                functionDeclaration.Index = indexIntLiteral;
            }

            // Parse identifier
            {
                if ( !TryGet( context, "Expected function identifier", () => context.Identifier(), out var identifierNode ) )
                    return false;

                FlowScriptIdentifier identifier = null;
                if ( !TryFunc( identifierNode, "Failed to parse function identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                    return false;

                identifier.ExpressionValueType = FlowScriptValueType.Function;

                functionDeclaration.Identifier = identifier;
            }

            // Parse parameter list
            {
                if ( !TryGet( context, "Expected function parameter list", () => context.parameterList(), out var parameterListContext ) )
                    return false;

                List<FlowScriptParameter> parameters = null;
                if ( !TryFunc( parameterListContext, "Failed to parse function parameter list", () => TryParseParameterList( parameterListContext, out parameters ) ) )
                    return false;

                functionDeclaration.Parameters = parameters;
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

            identifier.ExpressionValueType = FlowScriptValueType.Procedure;

            procedureDeclaration.Identifier = identifier;

            // Parse parameter list
            if ( !TryGet( context, "Expected procedure parameter list", () => context.parameterList(), out var parameterListContext ) )
                return false;

            List<FlowScriptParameter> parameters = null;
            if ( !TryFunc( parameterListContext, "Failed to parse procedure parameter list", () => TryParseParameterList( parameterListContext, out parameters ) ) )
                return false;

            procedureDeclaration.Parameters = parameters;

            // Parse body
            if ( TryGet( context, () => context.compoundStatement(), out var compoundStatementContext))
            {
                FlowScriptCompoundStatement body = null;
                if ( !TryFunc( compoundStatementContext, "Failed to parse procedure body", () => TryParseCompoundStatement( compoundStatementContext, out body ) ) )
                    return false;

                procedureDeclaration.Body = body;
            }

            return true;
        }

        private bool TryParseVariableDeclaration( FlowScriptParser.VariableDeclarationStatementContext context, out FlowScriptVariableDeclaration variableDeclaration )
        {
            LogContextInfo( context );

            variableDeclaration = CreateAstNode<FlowScriptVariableDeclaration>( context );

            // Parse modifier(s)
            if ( TryGet( context, () => context.Global(), out var globalNode))
            {           
                var modifier = CreateAstNode<FlowScriptVariableModifier>( globalNode );
                modifier.ModifierType = FlowScriptModifierType.Global;

                variableDeclaration.Modifiers.Add( modifier );
            }

            // Parse type identifier
            if ( !TryGet( context, "Expected variable type", () => context.TypeIdentifier(), out var typeIdentifierNode ) )
                return false;

            FlowScriptTypeIdentifier typeIdentifier = null;
            if ( !TryFunc( typeIdentifierNode, "Failed to parse variable type identifier", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                return false;

            variableDeclaration.Type = typeIdentifier;

            // Parse identifier
            if ( !TryGet( context, "Expected variable identifier", () => context.Identifier(), out var identifierNode ) )
                return false;

            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse variable identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                return false;

            // Resolve the identifier value type as it's known
            identifier.ExpressionValueType = variableDeclaration.Type.ValueType;

            variableDeclaration.Identifier = identifier;

            // Parse expression
            if ( TryGet( context, () => context.expression(), out var expressionContext))
            {
                FlowScriptExpression initializer = null;
                if ( !TryFunc( expressionContext, "Failed to parse variable initializer", () => TryParseExpression( expressionContext, out initializer ) ) )
                    return false;

                variableDeclaration.Initializer = initializer;
            }

            return true;
        }

        //
        // Expressions
        //
        private bool TryParseExpression( FlowScriptParser.ExpressionContext context, out FlowScriptExpression expression )
        {
            LogContextInfo( context );

            expression = null;

            // Parse null expression
            if ( TryCast<FlowScriptParser.NullExpressionContext>( context, out var nullExpressionContext ) )
            {
                mLogger.Info( "Null expression" );
                expression = null;
            }
            else if ( TryCast<FlowScriptParser.CompoundExpressionContext>( context, out var compoundExpressionContext ) )
            {
                mLogger.Info( "Todo: compound expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.CastExpressionContext>( context, out var castExpressionContext))
            {
                mLogger.Info( "Todo: cast" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.CallExpressionContext>( context, out var callExpressionContext ) )
            {
                FlowScriptCallExpression callExpression = null;
                if ( !TryFunc( callExpressionContext, "Failed to parse call expression", () => TryParseCallExpression( callExpressionContext, out callExpression ) ) )
                    return false;

                expression = callExpression;
            }
            else if ( TryCast<FlowScriptParser.UnaryPostfixExpressionContext>( context, out var unaryPostfixExpressionContext ) )
            {
                mLogger.Info( "Todo: unary postfix expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.UnaryPrefixExpressionContext>( context, out var unaryPrefixExpressionContext ) )
            {
                mLogger.Info( "Todo: unary prefix expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.MultiplicationExpressionContext>( context, out var multiplicationExpressionContext ) )
            {
                mLogger.Info( "Todo: multiplication expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.AdditionExpressionContext>( context, out var additionExpressionContext ) )
            {
                mLogger.Info( "Todo: addition expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.RelationalExpressionContext>( context, out var relationalExpressionContext ) )
            {
                mLogger.Info( "Todo: relational expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.EqualityExpressionContext>( context, out var equalityExpressionContext ) )
            {
                mLogger.Info( "Todo: equality expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.LogicalAndExpressionContext>( context, out var logicalAndExpressionContext ) )
            {
                mLogger.Info( "Todo: logical and expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.LogicalOrExpressionContext>( context, out var logicalOrExpressionContext ) )
            {
                mLogger.Info( "Todo: logical or expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.AssignmentExpressionContext>( context, out var assignmentExpressionContext ) )
            {
                mLogger.Info( "Todo: assignment expression" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.PrimaryExpressionContext>( context, out var primaryExpressionContext ) )
            {
                FlowScriptExpression primaryExpression = null;
                if ( !TryFunc( primaryExpressionContext, "Failed to parse primary expression", () => TryParsePrimaryExpression( primaryExpressionContext, out primaryExpression ) ) )
                    return false;

                expression = primaryExpression;
            }
            else
            {
                LogError( context, "Unknown expression" );
                return false;
            }

            return true;
        }

        private bool TryParseCallExpression( FlowScriptParser.CallExpressionContext context, out FlowScriptCallExpression callExpression )
        {
            LogContextInfo( context );

            callExpression = CreateAstNode<FlowScriptCallExpression>( context );

            if ( !TryGet( context, "Expected function or procedure identifier", () => context.Identifier(), out var identifierNode ) )
                return false;

            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse function or procedure identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                return false;

            callExpression.Identifier = identifier;

            if ( TryGet(context, () => context.expressionList(), out var expressionListContext))
            {
                if ( !TryGet( expressionListContext, "Expected expression(s)", () => expressionListContext.expression(), out var expressionContexts ) )
                    return false;

                foreach ( var expressionContext in expressionContexts )
                {
                    FlowScriptExpression expression = null;
                    if ( !TryFunc( expressionContext, "Failed to parse expression", () => TryParseExpression( expressionContext, out expression ) ) )
                        return false;

                    callExpression.Arguments.Add( expression );
                }
            }

            return true;
        }

        private bool TryParsePrimaryExpression( FlowScriptParser.PrimaryExpressionContext context, out FlowScriptExpression expression )
        {
            LogContextInfo( context );

            expression = null;
            if ( !TryGet( context, "Expected primary expression", () => context.primary(), out var primaryContext ) )
                return false;

            if ( TryCast<FlowScriptParser.ConstantExpressionContext>( primaryContext, out var constantExpressionContext ))
            {
                FlowScriptExpression constantExpression = null;
                if ( !TryFunc( constantExpressionContext, "Failed to parse constant expression", () => TryParseConstantExpression( constantExpressionContext, out constantExpression ) ) )
                    return false;

                expression = constantExpression;
            }
            else if ( TryCast<FlowScriptParser.IdentifierExpressionContext>( primaryContext, out var identifierExpressionContext ))
            {
                FlowScriptIdentifier identifier = null;
                if ( !TryFunc( identifierExpressionContext, "Failed to parse identifier expression", () => TryParseIdentifierExpression( identifierExpressionContext, out identifier ) ) )
                    return false;

                expression = identifier;
            }
            else
            {
                LogError( primaryContext, "Expected constant or identifier expression" );
                return false;
            }

            return true;
        }

        private bool TryParseConstantExpression( FlowScriptParser.ConstantExpressionContext context, out FlowScriptExpression expression )
        {
            LogContextInfo( context );

            expression = null;
            if ( !TryGet( context, "Expected constant", () => context.constant(), out var constantContext ) )
                return false;

            FlowScriptExpression constantExpression = null;
            if ( !TryFunc( constantContext, "Failed to parse literal", () => TryParseLiteral( constantContext, out constantExpression ) ) )
                return false;

            expression = constantExpression;

            return true;
        }

        private bool TryParseIdentifierExpression( FlowScriptParser.IdentifierExpressionContext context, out FlowScriptIdentifier identifier )
        {
            LogContextInfo( context );

            identifier = null;

            if ( !TryGet( context, "Expected identifier", () => context.Identifier(), out var identifierNode ) )
                return false;

            FlowScriptIdentifier parsedIdentifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse identifier", () => TryParseIdentifier( identifierNode, out parsedIdentifier ) ) )
                return false;

            identifier = parsedIdentifier;

            return true;
        }

        //
        // Literals
        //
        private bool TryParseLiteral( FlowScriptParser.ConstantContext context, out FlowScriptExpression expression )
        {
            LogContextInfo( context );

            expression = null;
            if ( TryGet(context, () => context.BoolLiteral(), out var boolLiteralContext))
            {
                if ( !TryParseBoolLiteral( boolLiteralContext, out var boolLiteral ) )
                    return false;

                expression = boolLiteral;
            }
            else if ( TryGet( context, () => context.IntLiteral(), out var intLiteralContext ) )
            {
                if ( !TryParseIntLiteral( intLiteralContext, out var intLiteral ) )
                    return false;

                expression = intLiteral;
            }
            else if ( TryGet( context, () => context.FloatLiteral(), out var floatLiteralContext ) )
            {
                if ( !TryParseFloatLiteral( floatLiteralContext, out var floatLiteral ) )
                    return false;

                expression = floatLiteral;
            }
            else if ( TryGet( context, () => context.StringLiteral(), out var stringLiteralContext ) )
            {
                if ( !TryParseStringLiteral( stringLiteralContext, out var stringLiteral ) )
                    return false;

                expression = stringLiteral;
            }
            else
            {
                LogError( context, "Expected literal" );
                return false;
            }

            return true;
        }

        private bool TryParseBoolLiteral( ITerminalNode node, out FlowScriptBoolLiteral literal )
        {
            literal = CreateAstNode<FlowScriptBoolLiteral>( node );

            bool value;
            if ( !bool.TryParse(node.Symbol.Text, out value) )
            {
                LogError( node.Symbol, "Invalid boolean value" );
                return false;
            }

            literal.Value = value;

            return true;
        }

        private bool TryParseIntLiteral( ITerminalNode node, out FlowScriptIntLiteral literal )
        {
            literal = CreateAstNode<FlowScriptIntLiteral>( node );

            int value = 0;
            string intString = node.Symbol.Text;

            if ( intString.StartsWith("0x", StringComparison.InvariantCultureIgnoreCase) )
            {
                // hex number
                if ( !int.TryParse( intString.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value ) )
                {
                    LogError( node.Symbol, "Invalid hexidecimal integer value" );
                    return false;
                }
            }
            else
            {
                // assume decimal
                if ( !int.TryParse( intString, out value ) )
                {
                    LogError( node.Symbol, "Invalid decimal integer value" );
                    return false;
                }
            }

            literal.Value = value;

            return true;
        }

        private bool TryParseFloatLiteral( ITerminalNode node, out FlowScriptFloatLiteral literal )
        {
            literal = CreateAstNode<FlowScriptFloatLiteral>( node );

            float value;
            if ( !float.TryParse( node.Symbol.Text, out value ) )
            {
                LogError( node.Symbol, "Invalid float value" );
                return false;
            }

            literal.Value = value;

            return true;
        }

        private bool TryParseStringLiteral( ITerminalNode node, out FlowScriptStringLiteral literal )
        {
            literal = CreateAstNode<FlowScriptStringLiteral>( node );
            literal.Value = node.Symbol.Text.Trim('\"');

            return true;
        }

        //
        // Parameter list
        //
        private bool TryParseParameterList( FlowScriptParser.ParameterListContext context, out List<FlowScriptParameter> parameters )
        {
            LogContextInfo( context );

            parameters = new System.Collections.Generic.List<FlowScriptParameter>();

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

            identifier.ExpressionValueType = parameter.TypeIdentifier.ValueType;

            parameter.Identifier = identifier;


            return true;
        }

        //
        // Identifiers
        //
        private bool TryParseTypeIdentifier( ITerminalNode node, out FlowScriptTypeIdentifier identifier )
        {
            identifier = CreateAstNode<FlowScriptTypeIdentifier>( node );
            identifier.Text = node.Symbol.Text;

            if ( !Enum.TryParse<FlowScriptValueType>( identifier.Text, true, out var primitiveType ) )
            {
                LogError( node.Symbol, $"Unknown value type: {identifier.Text }" );
                return false;
            }

            identifier.ValueType = primitiveType;

            return true;
        }

        private bool TryParseIdentifier(ITerminalNode node, out FlowScriptIdentifier identifier)
        {
            identifier = CreateAstNode<FlowScriptIdentifier>( node );
            identifier.Text = node.Symbol.Text;

            return true;
        }

        //
        // Parse helpers
        //
        private T CreateAstNode<T>( ParserRuleContext context ) where T : FlowScriptSyntaxNode, new()
        {
            T instance = new T();
            instance.SourceInfo = ParseSourceInfo( context.Start );

            return instance;
        }

        private T CreateAstNode<T>( ITerminalNode node ) where T : FlowScriptSyntaxNode, new()
        {
            T instance = new T();
            instance.SourceInfo = ParseSourceInfo( node.Symbol );

            return instance;
        }

        private FlowScriptSourceInfo ParseSourceInfo( IToken token )
        {
            return new FlowScriptSourceInfo( token.Line, token.Column, token.TokenSource.SourceName );
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
