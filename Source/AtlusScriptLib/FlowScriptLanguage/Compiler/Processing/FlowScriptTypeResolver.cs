using System.Collections.Generic;
using System.Diagnostics;

using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler.Processing
{
    public class FlowScriptTypeResolver
    {
        private Logger mLogger;
        private Dictionary<string, FlowScriptDeclaration> mDeclaredIdentifiers;

        public FlowScriptTypeResolver()
        {
            mLogger = new Logger( nameof( FlowScriptTypeResolver ) );
            mDeclaredIdentifiers = new Dictionary<string, FlowScriptDeclaration>();
        }

        /// <summary>
        /// Adds a resolver log listener. Use this if you want to see what went wrong during resolving.
        /// </summary>
        /// <param name="listener">The listener to add.</param>
        public void AddListener( LogListener listener )
        {
            listener.Subscribe( mLogger );
        }

        public bool TryResolveTypes( FlowScriptCompilationUnit compilationUnit )
        {
            ScanForDeclarations( compilationUnit );

            if ( !TryResolveTypesInCompilationUnit( compilationUnit ) )
                return false;

            return true;
        }

        private void ScanForDeclarations( FlowScriptCompilationUnit compilationUnit )
        {
            var scanner = new FlowScriptDeclarationScanner();
            var declarations = scanner.Scan( compilationUnit );
            foreach ( var declaration in declarations )
                RegisterDeclaration( declaration );
        }

        private void RegisterDeclaration( FlowScriptDeclaration declaration )
        {
            mDeclaredIdentifiers[declaration.Identifier.Text] = declaration;
        }

        // Resolving types
        private bool TryResolveTypesInCompilationUnit( FlowScriptCompilationUnit compilationUnit )
        {
            if ( !TryResolveTypesInStatements( compilationUnit.Statements ) )
                return false;

            return true;
        }

        private bool TryResolveTypesInStatements( IEnumerable<FlowScriptStatement> statements )
        {
            foreach ( var statement in statements )
            {
                if ( !TryResolveTypesInStatement( statement ) )
                    return false;
            }

            return true;
        }

        private bool TryResolveTypesInStatement( FlowScriptStatement statement )
        {
            if ( statement is FlowScriptCompoundStatement compoundStatement )
            {
                if ( !TryResolveTypesInStatements( compoundStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptDeclaration declaration )
            {
                if ( !TryResolveTypesInDeclaration( declaration ) )
                    return false;
            }
            else if ( statement is FlowScriptExpression expression )
            {
                if ( !TryResolveTypesInExpression( expression ) )
                    return false;
            }
            else if ( statement is FlowScriptIfStatement ifStatement )
            {
                if ( !TryResolveTypesInIfStatement( ifStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptReturnStatement returnStatement )
            {
                if ( returnStatement.Value != null )
                {
                    if ( !TryResolveTypesInExpression( returnStatement.Value ) )
                        return false;
                }
            }
            else if ( statement is FlowScriptGotoStatement gotoStatement )
            {
                if ( !TryResolveTypesInIdentifier( gotoStatement.LabelIdentifier ) )
                    return false;
            }
            else
            {
                mLogger.Info( $"No types resolved in statement '{statement}'" );
                //return false;
            }

            return true;
        }

        private bool TryResolveTypesInDeclaration( FlowScriptDeclaration declaration )
        {
            if ( !TryResolveTypesInIdentifier( declaration.Identifier ) )
                return false;

            if ( declaration is FlowScriptProcedureDeclaration procedureDeclaration )
            {
                if ( procedureDeclaration.Body != null )
                {
                    if ( !TryResolveTypesInStatements( procedureDeclaration.Body ) )
                        return false;
                }
            }
            else if ( declaration is FlowScriptVariableDeclaration variableDeclaration )
            {
                if ( variableDeclaration.Initializer != null )
                {
                    if ( !TryResolveTypesInExpression( variableDeclaration.Initializer ) )
                        return false;
                }
            }

            return true;
        }

        private bool TryResolveTypesInExpression( FlowScriptExpression expression )
        {
            LogInfo( expression, $"Resolving expression {expression}" );

            if ( expression is FlowScriptCallOperator callExpression )
            {
                if ( !TryResolveTypesInCallExpression( callExpression ) )
                    return false;
            }
            else if ( expression is FlowScriptUnaryExpression unaryExpression )
            {
                if ( !TryResolveTypesInExpression( unaryExpression.Operand ) )
                    return false;

                unaryExpression.ExpressionValueType = unaryExpression.Operand.ExpressionValueType;
            }
            else if ( expression is FlowScriptBinaryExpression binaryExpression )
            {
                if ( !TryResolveTypesInExpression( binaryExpression.Left ) )
                    return false;

                if ( !TryResolveTypesInExpression( binaryExpression.Right ) )
                    return false;

                if ( !(expression is FlowScriptEqualityOperator || expression is FlowScriptNonEqualityOperator ||
                     expression is FlowScriptGreaterThanOperator || expression is FlowScriptGreaterThanOrEqualOperator ||
                     expression is FlowScriptLessThanOperator || expression is FlowScriptLessThanOrEqualOperator ||
                     expression is FlowScriptLogicalAndOperator || expression is FlowScriptLogicalOrOperator) )
                {
                    binaryExpression.ExpressionValueType = binaryExpression.Left.ExpressionValueType;
                }
            }
            else if ( expression is FlowScriptIdentifier identifier )
            {
                if ( !TryResolveTypesInIdentifier( identifier ) )
                    return false;
            }
            else
            {
                if ( expression.ExpressionValueType == FlowScriptValueType.Unresolved )
                {
                    LogError( expression, $"Unresolved expression: {expression}" );
                    return false;
                }
            }

            LogInfo( expression, $"Resolved expression {expression} to type {expression.ExpressionValueType}" );

            return true;
        }

        private bool TryResolveTypesInCallExpression( FlowScriptCallOperator callExpression )
        {
            if ( !mDeclaredIdentifiers.TryGetValue( callExpression.Identifier.Text, out var declaration ) )
            {
                LogError( callExpression, $"Call expression references undeclared identifier '{callExpression.Identifier.Text}'" );
            }

            if ( declaration is FlowScriptFunctionDeclaration functionDeclaration )
            {
                callExpression.ExpressionValueType = functionDeclaration.ReturnType.ValueType;
                callExpression.Identifier.ExpressionValueType = FlowScriptValueType.Function;
            }
            else if ( declaration is FlowScriptProcedureDeclaration procedureDeclaration )
            {
                callExpression.ExpressionValueType = procedureDeclaration.ReturnType.ValueType;
                callExpression.Identifier.ExpressionValueType = FlowScriptValueType.Procedure;
            }
            else
            {
                LogError( callExpression, "Invalid call expression. Expected function or procedure identifier" );
                return false;
            }

            foreach ( var arg in callExpression.Arguments )
            {
                if ( !TryResolveTypesInExpression( arg ) )
                    return false;
            }

            return true;
        }

        private bool TryResolveTypesInIdentifier( FlowScriptIdentifier identifier )
        {
            if ( !mDeclaredIdentifiers.TryGetValue( identifier.Text, out var declaration ) )
            {
                LogError( identifier, $"Identifiers references undeclared identifier '{identifier.Text}'" );
            }

            if ( declaration is FlowScriptFunctionDeclaration functionDeclaration )
            {
                identifier.ExpressionValueType = FlowScriptValueType.Function;
            }
            else if ( declaration is FlowScriptProcedureDeclaration procedureDeclaration )
            {
                identifier.ExpressionValueType = FlowScriptValueType.Procedure;
            }
            else if ( declaration is FlowScriptVariableDeclaration variableDeclaration )
            {
                identifier.ExpressionValueType = variableDeclaration.Type.ValueType;
            }
            else if ( declaration is FlowScriptLabelDeclaration labelDeclaration )
            {
                identifier.ExpressionValueType = FlowScriptValueType.Label;
            }
            else
            {
                LogError( identifier, "Invalid identifier. Expected function, procedure, variable or label identifier" );
                return false;
            }

            return true;
        }

        private bool TryResolveTypesInIfStatement( FlowScriptIfStatement ifStatement )
        {
            if ( !TryResolveTypesInExpression( ifStatement.Condition ) )
                return false;

            if ( !TryResolveTypesInStatements( ifStatement.Body ) )
                return false;

            if ( !TryResolveTypesInStatements( ifStatement.ElseStatements ) )
                return false;

            return true;
        }

        // Logging
        private void LogInfo( FlowScriptSyntaxNode node, string message )
        {
            mLogger.Info( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
        }

        private void LogError( FlowScriptSyntaxNode node, string message )
        {
            mLogger.Error( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
            if ( Debugger.IsAttached )
                Debugger.Break();
        }
    }
}
