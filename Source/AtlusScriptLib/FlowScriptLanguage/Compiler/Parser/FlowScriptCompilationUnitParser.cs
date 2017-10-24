using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;

using Antlr4.Runtime;
using Antlr4.Runtime.Tree;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Syntax;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser.Grammar;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler.Parser
{
    /// <summary>
    /// Represents a parser that turns ANTLR's parse tree into an abstract syntax tree (AST).
    /// </summary>
    public class FlowScriptCompilationUnitParser
    {
        private readonly Logger mLogger;

        public FlowScriptCompilationUnitParser()
        {
            mLogger = new Logger( nameof( FlowScriptCompilationUnitParser ) );
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
            LogInfo( "Start parsing compilation unit" );

            LogContextInfo( context );

            compilationUnit = CreateAstNode<FlowScriptCompilationUnit>( context );

            // Parse using statements
            if ( TryGet( context, context.importStatement, out var importContexts ) )
            {
                List<FlowScriptImport> imports = null;
                if ( !TryFunc( context, "Failed to parse imports", () => TryParseImports( importContexts, out imports ) ) )
                    return false;

                compilationUnit.Imports = imports;
            }

            // Parse statements
            if ( !TryGet( context, "Expected statement(s)", context.declarationStatement, out var statementContexts ) )
                return false;

            List<FlowScriptDeclaration> statements = null;
            if ( !TryFunc( context, "Failed to parse statement(s)", () => TryParseDeclarationStatements( statementContexts, out statements ) ) )
                return false;

            compilationUnit.Declarations = statements;

            LogInfo( "Done parsing compilation unit" );

            return true;
        }

        //
        // Imports
        //
        private bool TryParseImports( FlowScriptParser.ImportStatementContext[] contexts, out System.Collections.Generic.List<FlowScriptImport> imports )
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

            if ( !TryGet( context, "Expected file path", context.StringLiteral, out var filePathNode ) )
                return false;

            if ( !TryGet( context, "Expected file path", () => filePathNode.Symbol.Text, out var filePath ) )
                return false;

            import = CreateAstNode<FlowScriptImport>( context );
            import.CompilationUnitFileName = filePath.Trim( '"' );

            return true;
        }

        //
        // Statements
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
            if ( TryGet( context, context.nullStatement, out var nullStatementContext ) )
            {
                statement = CreateAstNode<FlowScriptNullStatement>( nullStatementContext );
            }
            else if ( TryGet( context, context.compoundStatement, out var compoundStatementContext ) )
            {
                FlowScriptCompoundStatement compoundStatement = null;
                if ( !TryFunc( compoundStatementContext, "Failed to parse compound statement", () => TryParseCompoundStatement( compoundStatementContext, out compoundStatement ) ) )
                    return false;

                statement = compoundStatement;
            }
            else if ( TryGet( context, context.declarationStatement, out var declarationContext ) )
            {
                FlowScriptDeclaration declaration = null;
                if ( !TryFunc( declarationContext, "Failed to parse declaration", () => TryParseDeclaration( declarationContext, out declaration ) ) )
                    return false;

                statement = declaration;
            }
            else if ( TryGet( context, context.expression, out var expressionContext ) )
            {
                FlowScriptExpression expression = null;
                if ( !TryFunc( expressionContext, "Failed to parse expression", () => TryParseExpression( expressionContext, out expression ) ) )
                    return false;

                statement = expression;
            }
            else if ( TryGet( context, context.ifStatement, out var ifStatementContext ) )
            {
                FlowScriptIfStatement ifStatement = null;
                if ( !TryFunc( ifStatementContext, "Failed to parse if statement", () => TryParseIfStatement( ifStatementContext, out ifStatement ) ) )
                    return false;

                statement = ifStatement;
            }
            else if ( TryGet( context, context.forStatement, out var forStatementContext ) )
            {
                FlowScriptForStatement forStatement = null;
                if ( !TryFunc( forStatementContext, "Failed to parse for statement", () => TryParseForStatement( forStatementContext, out forStatement ) ) )
                    return false;

                statement = forStatement;
            }
            else if ( TryGet( context, context.whileStatement, out var whileStatementContext ) )
            {
                FlowScriptWhileStatement whileStatement = null;
                if ( !TryFunc( whileStatementContext, "Failed to parse while statement", () => TryParseWhileStatement( whileStatementContext, out whileStatement ) ) )
                    return false;

                statement = whileStatement;
            }
            else if ( TryGet( context, context.gotoStatement, out var gotoStatementContext ) )
            {
                FlowScriptGotoStatement gotoStatement = null;
                if ( !TryFunc( ifStatementContext, "Failed to parse goto statement", () => TryParseGotoStatement( gotoStatementContext, out gotoStatement ) ) )
                    return false;

                statement = gotoStatement;
            }
            else if ( TryGet( context, context.returnStatement, out var returnStatementContext ) )
            {
                FlowScriptReturnStatement returnStatement = null;
                if ( !TryFunc( ifStatementContext, "Failed to parse return statement", () => TryParseReturnStatement( returnStatementContext, out returnStatement ) ) )
                    return false;

                statement = returnStatement;
            }
            else if ( TryGet( context, context.breakStatement, out var breakStatement ) )
            {
                statement = CreateAstNode<FlowScriptBreakStatement>( breakStatement );
            }
            else if ( TryGet( context, context.continueStatement, out var continueStatement ) )
            {
                statement = CreateAstNode<FlowScriptContinueStatement>( continueStatement );
            }
            else if ( TryGet( context, context.switchStatement, out var switchStatementContext ) )
            {
                if ( !TryParseSwitchStatement( switchStatementContext, out var switchStatement ) )
                {
                    LogError( switchStatementContext, "Failed to parse switch statement" );
                    return false;
                }

                statement = switchStatement;
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

            if ( !TryGet( context, "Expected statement(s)", context.statement, out var statementContexts ) )
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
        private bool TryParseDeclarationStatements( FlowScriptParser.DeclarationStatementContext[] contexts, out List<FlowScriptDeclaration> statements )
        {
            statements = new List<FlowScriptDeclaration>();

            foreach ( var context in contexts )
            {
                FlowScriptDeclaration statement = null;
                if ( !TryFunc( context, "Failed to parse declaration", () => TryParseDeclaration( context, out statement ) ) )
                    return false;

                statements.Add( statement );
            }

            return true;
        }

        private bool TryParseDeclaration( FlowScriptParser.DeclarationStatementContext context, out FlowScriptDeclaration declaration )
        {
            LogContextInfo( context );

            declaration = null;

            // Parse function declaration statement
            if ( TryGet( context, context.functionDeclarationStatement, out var functionDeclarationContext ) )
            {
                FlowScriptFunctionDeclaration functionDeclaration = null;
                if ( !TryFunc( functionDeclarationContext, "Failed to parse function declaration", () => TryParseFunctionDeclaration( functionDeclarationContext, out functionDeclaration ) ) )
                    return false;

                declaration = functionDeclaration;
            }
            else if ( TryGet( context, context.procedureDeclarationStatement, out var procedureDeclarationContext ) )
            {
                FlowScriptProcedureDeclaration procedureDeclaration = null;
                if ( !TryFunc( procedureDeclarationContext, "Failed to parse procedure declaration", () => TryParseProcedureDeclaration( procedureDeclarationContext, out procedureDeclaration ) ) )
                    return false;

                declaration = procedureDeclaration;
            }
            else if ( TryGet( context, context.variableDeclarationStatement, out var variableDeclarationContext ) )
            {
                FlowScriptVariableDeclaration variableDeclaration = null;
                if ( !TryFunc( variableDeclarationContext, "Failed to parse variable declaration", () => TryParseVariableDeclaration( variableDeclarationContext, out variableDeclaration ) ) )
                    return false;

                declaration = variableDeclaration;
            }
            else if ( TryGet( context, context.enumTypeDeclarationStatement, out var enumDeclarationContext ) )
            {
                FlowScriptEnumDeclaration enumDeclaration = null;
                if ( !TryFunc( enumDeclarationContext, "Failed to parse enum declaration", () => TryParseEnumDeclaration( enumDeclarationContext, out enumDeclaration ) ) )
                    return false;

                declaration = enumDeclaration;
            }
            else if ( TryGet( context, context.labelDeclarationStatement, out var labelDeclarationContext ) )
            {
                FlowScriptLabelDeclaration labelDeclaration = null;
                if ( !TryFunc( labelDeclarationContext, "Failed to parse label declaration", () => TryParseLabelDeclaration( labelDeclarationContext, out labelDeclaration ) ) )
                    return false;

                declaration = labelDeclaration;
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

            int identifierIndex = 0;
            // Parse return type
            {
                if ( !TryGet( context, "Expected function return type", context.PrimitiveTypeIdentifier, out var typeIdentifierNode ) )
                {
                    if ( !TryGet( context, "Expected function return type", () => context.Identifier(0), out typeIdentifierNode ) )
                    {
                        return false;
                    }

                    identifierIndex = 1;
                }

                FlowScriptTypeIdentifier typeIdentifier = null;
                if ( !TryFunc( typeIdentifierNode, "Failed to parse function return type identifier", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                    return false;

                functionDeclaration.ReturnType = typeIdentifier;
            }

            // Parse index
            {
                if ( !TryGet( context, "Expected function index", context.IntLiteral, out var indexNode ) )
                    return false;

                FlowScriptIntLiteral indexIntLiteral = null;
                if ( !TryFunc( indexNode, "Failed to parse function index", () => TryParseIntLiteral( indexNode, out indexIntLiteral ) ) )
                    return false;

                functionDeclaration.Index = indexIntLiteral;
            }

            // Parse identifier
            {
                if ( !TryGet( context, "Expected function identifier", () => context.Identifier( identifierIndex ), out var identifierNode ) )
                    return false;

                FlowScriptIdentifier identifier = null;
                if ( !TryFunc( identifierNode, "Failed to parse function identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                    return false;

                identifier.ExpressionValueType = FlowScriptValueType.Function;

                functionDeclaration.Identifier = identifier;
            }

            // Parse parameter list
            {
                if ( !TryGet( context, "Expected function parameter list", context.parameterList, out var parameterListContext ) )
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
            if ( !TryGet( context, "Expected procedure return type", context.TypeIdentifier, out var typeIdentifierNode ) )
                return false;

            FlowScriptTypeIdentifier typeIdentifier = null;
            if ( !TryFunc( typeIdentifierNode, "Failed to parse procedure return type identifier", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                return false;

            procedureDeclaration.ReturnType = typeIdentifier;

            // Parse identifier
            ITerminalNode identifierNode;

            if ( !TryGet( context, context.ProcedureIdentifier, out identifierNode ) )
            {
                if ( !TryGet( context, "Expected procedure identifier", context.Identifier, out identifierNode ) )
                    return false;
            }

            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse procedure identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                return false;

            identifier.ExpressionValueType = FlowScriptValueType.Procedure;

            procedureDeclaration.Identifier = identifier;

            // Parse parameter list
            if ( !TryGet( context, "Expected procedure parameter list", context.parameterList, out var parameterListContext ) )
                return false;

            List<FlowScriptParameter> parameters = null;
            if ( !TryFunc( parameterListContext, "Failed to parse procedure parameter list", () => TryParseParameterList( parameterListContext, out parameters ) ) )
                return false;

            procedureDeclaration.Parameters = parameters;

            // Parse body
            if ( TryGet( context, context.compoundStatement, out var compoundStatementContext ) )
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
            if ( TryGet( context, context.variableModifier, out var variableModifierContext ) )
            {
                if ( !TryParseVariableModifier( variableModifierContext, out var modifier ) )
                {
                    LogError( variableModifierContext, "Failed to parse variable modifier" );
                    return false;
                }

                variableDeclaration.Modifier = modifier;
            }

            // Parse type identifier
            {
                if ( !TryGet( context, "Expected variable type", context.TypeIdentifier, out var typeIdentifierNode ) )
                    return false;

                FlowScriptTypeIdentifier typeIdentifier = null;
                if ( !TryFunc( typeIdentifierNode, "Failed to parse variable type identifier", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                    return false;

                variableDeclaration.Type = typeIdentifier;
            }

            // Parse identifier
            {
                if ( !TryGet( context, "Expected variable identifier", context.Identifier, out var identifierNode ) )
                    return false;

                FlowScriptIdentifier identifier = null;
                if ( !TryFunc( identifierNode, "Failed to parse variable identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                    return false;

                // Resolve the identifier value type as it's known
                identifier.ExpressionValueType = variableDeclaration.Type.ValueType;

                variableDeclaration.Identifier = identifier;
            }

            // Parse expression
            if ( TryGet( context, context.expression, out var expressionContext ) )
            {
                FlowScriptExpression initializer = null;
                if ( !TryFunc( expressionContext, "Failed to parse variable initializer", () => TryParseExpression( expressionContext, out initializer ) ) )
                    return false;

                variableDeclaration.Initializer = initializer;
            }

            return true;
        }

        private bool TryParseVariableModifier( FlowScriptParser.VariableModifierContext context, out FlowScriptVariableModifier modifier )
        {
            if ( TryGet( context, context.Static, out var staticNode ) )
            {
                modifier = CreateAstNode<FlowScriptVariableModifier>( staticNode );
                modifier.ModifierType = FlowScriptModifierType.Static;
            }
            else if ( TryGet( context, context.Const, out var constNode ) )
            {
                modifier = CreateAstNode<FlowScriptVariableModifier>( constNode );
                modifier.ModifierType = FlowScriptModifierType.Constant;
            }
            else
            {
                LogError( context, "Invalid variable modifier" );
                modifier = null;
                return false;
            }

            return true;
        }

        private bool TryParseEnumDeclaration( FlowScriptParser.EnumTypeDeclarationStatementContext context, out FlowScriptEnumDeclaration enumDeclaration )
        {
            LogContextInfo( context );

            enumDeclaration = CreateAstNode< FlowScriptEnumDeclaration >( context );

            // Parse identifier
            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( context.Identifier(), "Failed to parse enum identifier", () => TryParseIdentifier( context.Identifier(), out identifier ) ) )
                return false;

            enumDeclaration.Identifier = identifier;

            // Parse values
            List<FlowScriptEnumValueDeclaration> values = null;
            if ( !TryFunc( context.enumValueList(), "Failed to parse enum values", () => TryParseEnumValueList( context.enumValueList(), out values ) ) )
                return false;

            enumDeclaration.Values = values;

            return true;
        }

        private bool TryParseEnumValueList( FlowScriptParser.EnumValueListContext context, out List< FlowScriptEnumValueDeclaration > values )
        {
            values = new List< FlowScriptEnumValueDeclaration >();

            foreach ( var valueContext in context.enumValueDeclaration() )
            {
                var value = CreateAstNode< FlowScriptEnumValueDeclaration >( valueContext );

                // Parse identifier
                FlowScriptIdentifier identifier = null;
                if ( !TryFunc( valueContext.Identifier(), "Failed to parse enum value identifier", () => TryParseIdentifier( valueContext.Identifier(), out identifier ) ) )
                    return false;

                value.Identifier = identifier;

                if ( valueContext.expression() != null )
                {
                    // Parse value expression
                    FlowScriptExpression enumValue = null;

                    if ( !TryFunc( valueContext.expression(), "Failed to parse enum value", () => TryParseExpression( valueContext.expression(), out enumValue ) ) )
                        return false;

                    value.Value = enumValue;
                }

                values.Add( value );
            }

            return true;
        }

        private bool TryParseLabelDeclaration( FlowScriptParser.LabelDeclarationStatementContext context, out FlowScriptLabelDeclaration labelDeclaration )
        {
            LogContextInfo( context );

            labelDeclaration = CreateAstNode<FlowScriptLabelDeclaration>( context );

            // Parse identifier
            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( context.Identifier(), "Failed to parse label identifier", () => TryParseIdentifier( context.Identifier(), out identifier ) ) )
                return false;

            labelDeclaration.Identifier = identifier;

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
                mLogger.Error( "Null expression" );
                expression = null;
            }
            else if ( TryCast<FlowScriptParser.CompoundExpressionContext>( context, out var compoundExpressionContext ) )
            {
                if ( !TryParseExpression( compoundExpressionContext.expression(), out expression ) )
                    return false;
            }
            else if ( TryCast<FlowScriptParser.CastExpressionContext>( context, out var castExpressionContext ) )
            {
                mLogger.Error( "Todo: cast" );
                return false;
            }
            else if ( TryCast<FlowScriptParser.MemberAccessExpressionContext>( context, out var memberAccessExpressionContext ) )
            {
                FlowScriptMemberAccessExpression memberAccessExpression = null;
                if ( !TryFunc( memberAccessExpressionContext, "Failed to parse member access operator", () => TryParseMemberAccessExpression( memberAccessExpressionContext, out memberAccessExpression ) ) )
                    return false;

                expression = memberAccessExpression;
            }
            else if ( TryCast<FlowScriptParser.CallExpressionContext>( context, out var callExpressionContext ) )
            {
                FlowScriptCallOperator callExpression = null;
                if ( !TryFunc( callExpressionContext, "Failed to parse call operator", () => TryParseCallExpression( callExpressionContext, out callExpression ) ) )
                    return false;

                expression = callExpression;
            }
            else if ( TryCast<FlowScriptParser.UnaryPostfixExpressionContext>( context, out var unaryPostfixExpressionContext ) )
            {
                FlowScriptUnaryExpression unaryExpression = null;
                if ( !TryFunc( unaryPostfixExpressionContext, "Failed to parse unary postfix expression", () => TryParseUnaryPostfixExpression( unaryPostfixExpressionContext, out unaryExpression ) ) )
                    return false;

                expression = unaryExpression;
            }
            else if ( TryCast<FlowScriptParser.UnaryPrefixExpressionContext>( context, out var unaryPrefixExpressionContext ) )
            {
                FlowScriptUnaryExpression unaryExpression = null;
                if ( !TryFunc( unaryPrefixExpressionContext, "Failed to parse unary prefix expression", () => TryParseUnaryPrefixExpression( unaryPrefixExpressionContext, out unaryExpression ) ) )
                    return false;

                expression = unaryExpression;
            }
            else if ( TryCast<FlowScriptParser.MultiplicationExpressionContext>( context, out var multiplicationExpressionContext ) )
            {
                FlowScriptBinaryExpression binaryExpression = null;
                if ( !TryFunc( multiplicationExpressionContext, "Failed to parse multiplication expression", () => TryParseMultiplicationExpression( multiplicationExpressionContext, out binaryExpression ) ) )
                    return false;

                expression = binaryExpression;
            }
            else if ( TryCast<FlowScriptParser.AdditionExpressionContext>( context, out var additionExpressionContext ) )
            {
                FlowScriptBinaryExpression binaryExpression = null;
                if ( !TryFunc( additionExpressionContext, "Failed to parse addition expression", () => TryParseAdditionExpression( additionExpressionContext, out binaryExpression ) ) )
                    return false;

                expression = binaryExpression;
            }
            else if ( TryCast<FlowScriptParser.RelationalExpressionContext>( context, out var relationalExpressionContext ) )
            {
                FlowScriptBinaryExpression binaryExpression = null;
                if ( !TryFunc( relationalExpressionContext, "Failed to parse relational expression", () => TryParseRelationalExpression( relationalExpressionContext, out binaryExpression ) ) )
                    return false;

                expression = binaryExpression;
            }
            else if ( TryCast<FlowScriptParser.EqualityExpressionContext>( context, out var equalityExpressionContext ) )
            {
                FlowScriptBinaryExpression equalityExpression = null;
                if ( !TryFunc( equalityExpressionContext, "Failed to parse equality expression", () => TryParseEqualityExpression( equalityExpressionContext, out equalityExpression ) ) )
                    return false;

                expression = equalityExpression;
            }
            else if ( TryCast<FlowScriptParser.LogicalAndExpressionContext>( context, out var logicalAndExpressionContext ) )
            {
                FlowScriptBinaryExpression binaryExpression = null;
                if ( !TryFunc( logicalAndExpressionContext, "Failed to parse logical and expression", () => TryParseLogicalAndExpression( logicalAndExpressionContext, out binaryExpression ) ) )
                    return false;

                expression = binaryExpression;
            }
            else if ( TryCast<FlowScriptParser.LogicalOrExpressionContext>( context, out var logicalOrExpressionContext ) )
            {
                FlowScriptBinaryExpression binaryExpression = null;
                if ( !TryFunc( logicalOrExpressionContext, "Failed to parse logical or expression", () => TryParseLogicalOrExpression( logicalOrExpressionContext, out binaryExpression ) ) )
                    return false;

                expression = binaryExpression;
            }
            else if ( TryCast<FlowScriptParser.AssignmentExpressionContext>( context, out var assignmentExpressionContext ) )
            {
                FlowScriptBinaryExpression binaryExpression = null;
                if ( !TryFunc( assignmentExpressionContext, "Failed to parse assigment expression", () => TryParseAssignmentExpression( assignmentExpressionContext, out binaryExpression ) ) )
                    return false;

                expression = binaryExpression;
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

        private bool TryParseMemberAccessExpression( FlowScriptParser.MemberAccessExpressionContext context, out FlowScriptMemberAccessExpression memberAccessExpression )
        {
            memberAccessExpression = CreateAstNode< FlowScriptMemberAccessExpression >( context );

            FlowScriptIdentifier operand = null;
            if ( !TryFunc( context.Identifier(0), "Failed to parse member access operand", () => TryParseIdentifier( context.Identifier( 0 ), out operand ) ) )
                return false;

            memberAccessExpression.Operand = operand;

            FlowScriptIdentifier member = null;
            if ( !TryFunc( context.Identifier( 1 ), "Failed to parse member identifier", () => TryParseIdentifier( context.Identifier( 1 ), out member ) ) )
                return false;

            memberAccessExpression.Member = member;

            return true;
        }

        private bool TryParseCallExpression( FlowScriptParser.CallExpressionContext context, out FlowScriptCallOperator callExpression )
        {
            LogContextInfo( context );

            callExpression = CreateAstNode<FlowScriptCallOperator>( context );

            if ( !TryGet( context, "Expected function or procedure identifier", () => context.Identifier(), out var identifierNode ) )
                return false;

            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse function or procedure identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                return false;

            callExpression.Identifier = identifier;

            if ( TryGet( context, context.expressionList, out var expressionListContext ) )
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

        private bool TryParseUnaryPostfixExpression( FlowScriptParser.UnaryPostfixExpressionContext context, out FlowScriptUnaryExpression unaryExpression )
        {
            LogContextInfo( context );

            switch ( context.Op.Text )
            {
                case "--":
                    unaryExpression = CreateAstNode<FlowScriptPostfixDecrementOperator>( context );
                    break;

                case "++":
                    unaryExpression = CreateAstNode<FlowScriptPostfixIncrementOperator>( context );
                    break;

                default:
                    unaryExpression = null;
                    LogError( context, $"Invalid op for unary postfix expression: ${context.Op}" );
                    return false;
            }

            if ( !TryParseExpression( context.expression(), out var leftExpression ) )
                return false;

            unaryExpression.Operand = leftExpression;

            return true;
        }

        private bool TryParseUnaryPrefixExpression( FlowScriptParser.UnaryPrefixExpressionContext context, out FlowScriptUnaryExpression unaryExpression )
        {
            LogContextInfo( context );

            switch ( context.Op.Text )
            {
                case "!":
                    unaryExpression = CreateAstNode<FlowScriptLogicalNotOperator>( context );
                    break;

                case "-":
                    unaryExpression = CreateAstNode<FlowScriptNegationOperator>( context );
                    break;

                case "--":
                    unaryExpression = CreateAstNode<FlowScriptPrefixDecrementOperator>( context );
                    break;

                case "++":
                    unaryExpression = CreateAstNode<FlowScriptPrefixIncrementOperator>( context );
                    break;

                default:
                    unaryExpression = null;
                    LogError( context, $"Invalid op for unary prefix expression: ${context.Op}" );
                    return false;
            }

            if ( !TryParseExpression( context.expression(), out var leftExpression ) )
                return false;

            unaryExpression.Operand = leftExpression;

            return true;
        }

        private bool TryParseMultiplicationExpression( FlowScriptParser.MultiplicationExpressionContext context, out FlowScriptBinaryExpression binaryExpression )
        {
            LogContextInfo( context );

            if ( context.Op.Text == "*" )
            {
                binaryExpression = CreateAstNode<FlowScriptMultiplicationOperator>( context );
            }
            else if ( context.Op.Text == "/" )
            {
                binaryExpression = CreateAstNode<FlowScriptDivisionOperator>( context );
            }
            else
            {
                binaryExpression = null;
                LogError( context, $"Invalid op for multiplication expression: ${context.Op}" );
                return false;
            }

            // Left
            {
                if ( !TryParseExpression( context.expression( 0 ), out var leftExpression ) )
                    return false;

                binaryExpression.Left = leftExpression;
            }

            // Right
            {
                if ( !TryParseExpression( context.expression( 1 ), out var rightExpression ) )
                    return false;

                binaryExpression.Right = rightExpression;
            }

            return true;
        }

        private bool TryParseAdditionExpression( FlowScriptParser.AdditionExpressionContext context, out FlowScriptBinaryExpression binaryExpression )
        {
            LogContextInfo( context );

            if ( context.Op.Text == "+" )
            {
                binaryExpression = CreateAstNode<FlowScriptAdditionOperator>( context );
            }
            else if ( context.Op.Text == "-" )
            {
                binaryExpression = CreateAstNode<FlowScriptSubtractionOperator>( context );
            }
            else
            {
                binaryExpression = null;
                LogError( context, $"Invalid op for addition expression: ${context.Op}" );
                return false;
            }

            // Left
            {
                if ( !TryParseExpression( context.expression( 0 ), out var leftExpression ) )
                    return false;

                binaryExpression.Left = leftExpression;
            }

            // Right
            {
                if ( !TryParseExpression( context.expression( 1 ), out var rightExpression ) )
                    return false;

                binaryExpression.Right = rightExpression;
            }

            return true;
        }

        private bool TryParseRelationalExpression( FlowScriptParser.RelationalExpressionContext context, out FlowScriptBinaryExpression binaryExpression )
        {
            LogContextInfo( context );

            if ( context.Op.Text == "<" )
            {
                binaryExpression = CreateAstNode<FlowScriptLessThanOperator>( context );
            }
            else if ( context.Op.Text == ">" )
            {
                binaryExpression = CreateAstNode<FlowScriptGreaterThanOperator>( context );
            }
            else if ( context.Op.Text == "<=" )
            {
                binaryExpression = CreateAstNode<FlowScriptLessThanOrEqualOperator>( context );
            }
            else if ( context.Op.Text == ">=" )
            {
                binaryExpression = CreateAstNode<FlowScriptGreaterThanOrEqualOperator>( context );
            }
            else
            {
                binaryExpression = null;
                LogError( context, $"Invalid op for addition expression: ${context.Op}" );
                return false;
            }

            // Left
            {
                if ( !TryParseExpression( context.expression( 0 ), out var leftExpression ) )
                    return false;

                binaryExpression.Left = leftExpression;
            }

            // Right
            {
                if ( !TryParseExpression( context.expression( 1 ), out var rightExpression ) )
                    return false;

                binaryExpression.Right = rightExpression;
            }

            return true;
        }

        private bool TryParseEqualityExpression( FlowScriptParser.EqualityExpressionContext context, out FlowScriptBinaryExpression equalityExpression )
        {
            LogContextInfo( context );

            if ( context.Op.Text == "==" )
            {
                equalityExpression = CreateAstNode<FlowScriptEqualityOperator>( context );
            }
            else if ( context.Op.Text == "!=" )
            {
                equalityExpression = CreateAstNode<FlowScriptNonEqualityOperator>( context );
            }
            else
            {
                equalityExpression = null;
                LogError( context, $"Invalid op for equality expression: ${context.Op}" );
                return false;
            }

            // Left
            {
                if ( !TryParseExpression( context.expression( 0 ), out var leftExpression ) )
                    return false;

                equalityExpression.Left = leftExpression;
            }

            // Right
            {
                if ( !TryParseExpression( context.expression( 1 ), out var rightExpression ) )
                    return false;

                equalityExpression.Right = rightExpression;
            }

            return true;
        }

        private bool TryParseLogicalAndExpression( FlowScriptParser.LogicalAndExpressionContext context, out FlowScriptBinaryExpression binaryExpression )
        {
            LogContextInfo( context );

            binaryExpression = CreateAstNode<FlowScriptLogicalAndOperator>( context );

            // Left
            {
                if ( !TryParseExpression( context.expression( 0 ), out var leftExpression ) )
                    return false;

                binaryExpression.Left = leftExpression;
            }

            // Right
            {
                if ( !TryParseExpression( context.expression( 1 ), out var rightExpression ) )
                    return false;

                binaryExpression.Right = rightExpression;
            }

            return true;
        }

        private bool TryParseLogicalOrExpression( FlowScriptParser.LogicalOrExpressionContext context, out FlowScriptBinaryExpression binaryExpression )
        {
            LogContextInfo( context );

            binaryExpression = CreateAstNode<FlowScriptLogicalOrOperator>( context );

            // Left
            {
                if ( !TryParseExpression( context.expression( 0 ), out var leftExpression ) )
                    return false;

                binaryExpression.Left = leftExpression;
            }

            // Right
            {
                if ( !TryParseExpression( context.expression( 1 ), out var rightExpression ) )
                    return false;

                binaryExpression.Right = rightExpression;
            }

            return true;
        }

        private bool TryParseAssignmentExpression( FlowScriptParser.AssignmentExpressionContext context, out FlowScriptBinaryExpression binaryExpression )
        {
            LogContextInfo( context );

            switch ( context.Op.Text )
            {
                case "=":
                    binaryExpression = CreateAstNode<FlowScriptAssignmentOperator>( context );
                    break;

                case "+=":
                    binaryExpression = CreateAstNode<FlowScriptAdditionAssignmentOperator>( context );
                    break;

                case "-=":
                    binaryExpression = CreateAstNode<FlowScriptSubtractionAssignmentOperator>( context );
                    break;

                case "*=":
                    binaryExpression = CreateAstNode<FlowScriptMultiplicationAssignmentOperator>( context );
                    break;

                case "/=":
                    binaryExpression = CreateAstNode<FlowScriptDivisionAssignmentOperator>( context );
                    break;

                default:
                    LogError( context, $"Unknown assignment operator: { context.Op.Text }" );
                    binaryExpression = null;
                    return false;
            }

            // Left
            {
                if ( !TryParseIdentifier( context.Identifier(), out var leftExpression ) )
                    return false;

                binaryExpression.Left = leftExpression;
            }

            // Right
            {
                if ( !TryParseExpression( context.expression(), out var rightExpression ) )
                    return false;

                binaryExpression.Right = rightExpression;
            }

            return true;
        }

        private bool TryParsePrimaryExpression( FlowScriptParser.PrimaryExpressionContext context, out FlowScriptExpression expression )
        {
            LogContextInfo( context );

            expression = null;
            if ( !TryGet( context, "Expected primary expression", context.primary, out var primaryContext ) )
                return false;

            if ( TryCast<FlowScriptParser.ConstantExpressionContext>( primaryContext, out var constantExpressionContext ) )
            {
                FlowScriptExpression constantExpression = null;
                if ( !TryFunc( constantExpressionContext, "Failed to parse constant expression", () => TryParseConstantExpression( constantExpressionContext, out constantExpression ) ) )
                    return false;

                expression = constantExpression;
            }
            else if ( TryCast<FlowScriptParser.IdentifierExpressionContext>( primaryContext, out var identifierExpressionContext ) )
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
            if ( !TryGet( context, "Expected constant", context.constant, out var constantContext ) )
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

            if ( !TryGet( context, "Expected identifier", context.Identifier, out var identifierNode ) )
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
            if ( TryGet( context, context.BoolLiteral, out var boolLiteralContext ) )
            {
                if ( !TryParseBoolLiteral( boolLiteralContext, out var boolLiteral ) )
                    return false;

                expression = boolLiteral;
            }
            else if ( TryGet( context, context.IntLiteral, out var intLiteralContext ) )
            {
                if ( !TryParseIntLiteral( intLiteralContext, out var intLiteral ) )
                    return false;

                expression = intLiteral;
            }
            else if ( TryGet( context, context.FloatLiteral, out var floatLiteralContext ) )
            {
                if ( !TryParseFloatLiteral( floatLiteralContext, out var floatLiteral ) )
                    return false;

                expression = floatLiteral;
            }
            else if ( TryGet( context, context.StringLiteral, out var stringLiteralContext ) )
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
            if ( !bool.TryParse( node.Symbol.Text, out value ) )
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

            if ( intString.StartsWith( "0x", StringComparison.InvariantCultureIgnoreCase ) )
            {
                // hex number
                if ( !int.TryParse( intString.Substring( 2 ), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value ) )
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

            string floatString = node.Symbol.Text;
            if ( floatString.EndsWith( "f", StringComparison.InvariantCultureIgnoreCase ) )
            {
                floatString = floatString.Substring( 0, floatString.Length - 1 );
            }

            float value;
            if ( !float.TryParse( floatString, out value ) )
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
            literal.Value = node.Symbol.Text.Trim( '\"' );

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
            if ( !TryGet( context, "Expected parameter list", context.parameter, out var parameterContexts ) )
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
            if ( !TryGet( context, "Expected parameter type", context.TypeIdentifier, out var typeIdentifierNode ) )
                return false;

            FlowScriptTypeIdentifier typeIdentifier = null;
            if ( !TryFunc( typeIdentifierNode, "Failed to parse parameter type", () => TryParseTypeIdentifier( typeIdentifierNode, out typeIdentifier ) ) )
                return false;

            parameter.Type = typeIdentifier;

            // Parse identifier
            if ( !TryGet( context, "Expected parameter identifier", context.Identifier, out var identifierNode ) )
                return false;

            FlowScriptIdentifier identifier = null;
            if ( !TryFunc( identifierNode, "Failed to parse parameter identifier", () => TryParseIdentifier( identifierNode, out identifier ) ) )
                return false;

            identifier.ExpressionValueType = parameter.Type.ValueType;

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
                primitiveType = FlowScriptValueType.Int;
                //LogError( node.Symbol, $"Unknown value type: {identifier.Text }" );
                //return false;
            }

            identifier.ValueType = primitiveType;

            return true;
        }

        private bool TryParseIdentifier( ITerminalNode node, out FlowScriptIdentifier identifier )
        {
            identifier = CreateAstNode<FlowScriptIdentifier>( node );
            identifier.Text = node.Symbol.Text;

            return true;
        }


        //
        // If statement
        //
        private bool TryParseIfStatement( FlowScriptParser.IfStatementContext context, out FlowScriptIfStatement ifStatement )
        {
            LogContextInfo( context );

            ifStatement = CreateAstNode<FlowScriptIfStatement>( context );

            // Expression
            {
                if ( !TryGet( context, "Expected if condition expression", context.expression, out var expressionNode ) )
                    return false;

                FlowScriptExpression condition = null;
                if ( !TryFunc( expressionNode, "Failed to parse if condition expression", () => TryParseExpression( expressionNode, out condition ) ) )
                    return false;

                ifStatement.Condition = condition;
            }

            // Body
            {
                if ( !TryGet( context, "Expected if body", () => context.statement( 0 ), out var bodyContext ) )
                    return false;

                FlowScriptStatement body = null;
                if ( !TryFunc( bodyContext, "Failed to parse if body", () => TryParseStatement( bodyContext, out body ) ) )
                    return false;

                if ( body is FlowScriptCompoundStatement )
                {
                    ifStatement.Body = ( FlowScriptCompoundStatement )body;
                }
                else
                {
                    ifStatement.Body = CreateAstNode<FlowScriptCompoundStatement>( bodyContext );
                    ifStatement.Body.Statements.Add( body );
                }
            }

            // Else statement
            {
                if ( TryGet( context, () => context.statement( 1 ), out var elseBodyContext ) )
                {
                    FlowScriptStatement body = null;
                    if ( !TryFunc( elseBodyContext, "Failed to parse else body", () => TryParseStatement( elseBodyContext, out body ) ) )
                        return false;

                    if ( body is FlowScriptCompoundStatement )
                    {
                        ifStatement.ElseBody = ( FlowScriptCompoundStatement )body;
                    }
                    else
                    {
                        ifStatement.ElseBody = CreateAstNode<FlowScriptCompoundStatement>( elseBodyContext );
                        ifStatement.ElseBody.Statements.Add( body );
                    }
                }
            }

            return true;
        }

        //
        // For statement
        //
        private bool TryParseForStatement( FlowScriptParser.ForStatementContext context, out FlowScriptForStatement forStatement )
        {
            LogContextInfo( context );

            forStatement = CreateAstNode<FlowScriptForStatement>( context );

            if ( !TryParseStatement( context.statement( 0 ), out var initializer ) )
            {
                LogError( context.statement( 0 ), "Failed to parse for statement initializer" );
                return false;
            }

            forStatement.Initializer = initializer;

            if ( !TryParseExpression( context.expression( 0 ), out var condition ) )
            {
                LogError( context.statement( 0 ), "Failed to parse for statement condition" );
                return false;
            }

            forStatement.Condition = condition;

            if ( !TryParseExpression( context.expression( 1 ), out var afterLoop ) )
            {
                LogError( context.statement( 0 ), "Failed to parse for statement after loop expression" );
                return false;
            }

            forStatement.AfterLoop = afterLoop;

            if ( !TryParseStatement( context.statement( 1 ), out var body ) )
            {
                LogError( context.statement( 0 ), "Failed to parse for statement body" );
                return false;
            }

            if ( body is FlowScriptCompoundStatement )
            {
                forStatement.Body = ( FlowScriptCompoundStatement )body;
            }
            else
            {
                forStatement.Body = CreateAstNode<FlowScriptCompoundStatement>( context.statement( 1 ) );
                forStatement.Body.Statements.Add( body );
            }

            return true;
        }

        //
        // While statement
        //
        private bool TryParseWhileStatement( FlowScriptParser.WhileStatementContext context, out FlowScriptWhileStatement whileStatement )
        {
            LogContextInfo( context );

            whileStatement = CreateAstNode<FlowScriptWhileStatement>( context );

            if ( !TryParseExpression( context.expression(), out var condition ) )
            {
                LogError( context.expression(), "Failed to parse while statement condition" );
                return false;
            }

            whileStatement.Condition = condition;

            if ( !TryParseStatement( context.statement(), out var body ) )
            {
                LogError( context.statement(), "Failed to parse while statement body" );
                return false;
            }

            if ( body is FlowScriptCompoundStatement )
            {
                whileStatement.Body = ( FlowScriptCompoundStatement )body;
            }
            else
            {
                whileStatement.Body = CreateAstNode<FlowScriptCompoundStatement>( context.statement() );
                whileStatement.Body.Statements.Add( body );
            }

            return true;
        }

        //
        // Goto statement
        //
        private bool TryParseGotoStatement( FlowScriptParser.GotoStatementContext context, out FlowScriptGotoStatement gotoStatement )
        {
            LogContextInfo( context );

            gotoStatement = CreateAstNode<FlowScriptGotoStatement>( context );

            if ( !TryGet( context, context.Identifier, out var identifier ) )
            {
                LogError( context, "Expected goto label identifier" );
                return false;
            }

            if ( !TryParseIdentifier( identifier, out var target ) )
            {
                LogError( context, "Failed to parse goto label identifier" );
                return false;
            }

            gotoStatement.LabelIdentifier = target;

            return true;
        }

        //
        // Return statement
        //
        private bool TryParseReturnStatement( FlowScriptParser.ReturnStatementContext context, out FlowScriptReturnStatement returnStatement )
        {
            LogContextInfo( context );

            returnStatement = CreateAstNode<FlowScriptReturnStatement>( context );

            if ( TryGet( context, context.expression, out var expressionContext ) )
            {
                if ( !TryParseExpression( expressionContext, out var expression ) )
                {
                    LogError( expressionContext, "Failed to parse return statement expression" );
                    return false;
                }

                returnStatement.Value = expression;
            }

            return true;
        }

        private bool TryParseSwitchStatement( FlowScriptParser.SwitchStatementContext context, out FlowScriptSwitchStatement switchStatement )
        {
            LogContextInfo( context );

            switchStatement = CreateAstNode<FlowScriptSwitchStatement>( context );

            // Parse switch-on expression
            if ( !TryParseExpression( context.expression(), out var switchOn ) )
            {
                LogError( context.expression(), "Failed to parse switch statement 'switch-on' expression" );
                return false;
            }

            switchStatement.SwitchOn = switchOn;

            // Parse switch labels
            foreach ( var switchLabelContext in context.switchLabel() )
            {
                FlowScriptSwitchLabel label = null;

                if ( switchLabelContext.Case() != null )
                {
                    // Parse expression
                    if ( !TryParseExpression( switchLabelContext.expression(), out var condition ) )
                    {
                        LogError( context.expression(), "Failed to parse switch statement label expression" );
                        return false;
                    }

                    var conditionLabel = CreateAstNode<FlowScriptConditionSwitchLabel>( switchLabelContext );
                    conditionLabel.Condition = condition;

                    label = conditionLabel;
                }
                else
                {
                    label = CreateAstNode<FlowScriptDefaultSwitchLabel>( switchLabelContext );
                }

                // Parse statements
                if ( !TryParseStatements( switchLabelContext.statement(), out var body ))
                {
                    mLogger.Error( "Failed to parse switch statement label body" );
                    return false;
                }

                label.Body = body;
                switchStatement.Labels.Add( label );
            }

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

            return value != null;
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
            mLogger.Info( $"({context.Start.Line:D4}:{context.Start.Column:D4}) Entered parsing context {context.GetType().Name} rule: {FlowScriptParser.ruleNames[context.RuleIndex]}" );
        }

        private void LogError( ParserRuleContext context, string str )
        {
            mLogger.Error( $"({context.Start.Line:D4}:{context.Start.Column:D4}) {str}" );

            if ( Debugger.IsAttached )
                Debugger.Break();
        }

        private void LogError( IToken token, string message )
        {
            mLogger.Error( $"({token.Line:D4}:{token.Column:D4}) {message}" );

            if ( Debugger.IsAttached )
                Debugger.Break();
        }

        private void LogWarning( ParserRuleContext context, string str )
        {
            mLogger.Warning( $"({context.Start.Line:D4}:{context.Start.Column:D4}) {str}" );
        }

        private void LogInfo( string message )
        {
            mLogger.Info( $"            {message}" );
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
