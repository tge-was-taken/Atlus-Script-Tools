using System;
using System.Collections.Generic;
using System.Diagnostics;

using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler.Processing
{
    public class FlowScriptTypeResolver
    {
        private Logger mLogger;
        private Stack<FlowScriptDeclarationScope> mScopes;

        private FlowScriptDeclarationScope Scope => mScopes.Peek();

        public FlowScriptTypeResolver()
        {
            mLogger = new Logger( nameof( FlowScriptTypeResolver ) );
            mScopes = new Stack<FlowScriptDeclarationScope>();
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
            if ( !TryResolveTypesInCompilationUnit( compilationUnit ) )
                return false;

            return true;
        }

        // top level declarations are handled seperately to make them accessible throughout the entire file
        // regardless of scope
        private bool TryRegisterTopLevelDeclarations( FlowScriptCompilationUnit compilationUnit )
        {
            if ( !TryRegisterDeclarations( compilationUnit.Statements ) )
                return false;

            return true;
        }

        private bool TryRegisterDeclarations( IEnumerable<FlowScriptStatement> statements )
        {
            foreach ( var statement in statements )
            {
                if ( statement is FlowScriptDeclaration declaration )
                {
                    if ( !TryRegisterDeclaration( declaration ) )
                        return false;
                }
            }

            return true;
        }

        private bool TryRegisterDeclaration( FlowScriptDeclaration declaration )
        {
            if ( !Scope.TryRegisterDeclaration( declaration ) )
            {
                // Special case: forward declared declarations on top level
                if ( Scope.Parent != null )
                    return false;
            }

            return true;
        }

        private void PushScope()
        {
            if ( mScopes.Count != 0 )
                mScopes.Push( new FlowScriptDeclarationScope( Scope ) );
            else
                mScopes.Push( new FlowScriptDeclarationScope( null ) );
        }

        private void PopScope()
        {
            mScopes.Pop();
        }

        // Resolving types
        private bool TryResolveTypesInCompilationUnit( FlowScriptCompilationUnit compilationUnit )
        {
            PushScope();

            if ( !TryRegisterTopLevelDeclarations( compilationUnit ) )
                return false;

            foreach ( var statement in compilationUnit.Statements )
            {
                if ( !TryResolveTypesInStatement( statement ) )
                    return false;
            }

            PopScope();

            return true;
        }

        private bool TryResolveTypesInStatement( FlowScriptStatement statement )
        {
            if ( statement is FlowScriptCompoundStatement compoundStatement )
            {
                if ( !TryResolveTypesInCompoundStatement( compoundStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptDeclaration declaration )
            {
                if ( !TryRegisterDeclaration( declaration ) )
                    return false;

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
            else if ( statement is FlowScriptForStatement forStatement )
            {
                if ( !TryResolveTypesInForStatement( forStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptWhileStatement whileStatement )
            {
                if ( !TryResolveTypesInWhileStatement( whileStatement ) )
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
                gotoStatement.LabelIdentifier.ExpressionValueType = FlowScriptValueType.Label;
            }
            else
            {
                mLogger.Info( $"No types resolved in statement '{statement}'" );
                //return false;
            }

            return true;
        }

        private bool TryResolveTypesInCompoundStatement( FlowScriptCompoundStatement compoundStatement )
        {
            foreach ( var statement in compoundStatement )
            {
                if ( !TryResolveTypesInStatement( statement ) )
                    return false;
            }

            return true;
        }

        private bool TryResolveTypesInDeclaration( FlowScriptDeclaration declaration )
        {
            if ( declaration.DeclarationType != FlowScriptDeclarationType.Label )
            {
                if ( !TryResolveTypesInIdentifier( declaration.Identifier ) )
                    return false;
            }
            else
            {
                declaration.Identifier.ExpressionValueType = FlowScriptValueType.Label;
            }

            if ( declaration is FlowScriptProcedureDeclaration procedureDeclaration )
            {
                PushScope();

                if ( procedureDeclaration.Body != null )
                {
                    foreach ( var parameter in procedureDeclaration.Parameters )
                    {
                        var parameterDeclaration = new FlowScriptVariableDeclaration(
                            new List<FlowScriptVariableModifier>() { new FlowScriptVariableModifier() },
                            parameter.TypeIdentifier,
                            parameter.Identifier,
                            null );

                        if ( !TryRegisterDeclaration(parameterDeclaration) )
                        {
                            LogError( parameter, "Failed to register declaration for procedure parameter" );
                            return false;
                        }
                    }

                    if ( !TryResolveTypesInCompoundStatement( procedureDeclaration.Body ) )
                        return false;
                }

                PopScope();
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
            if ( !Scope.TryGetDeclaration( callExpression.Identifier, out var declaration ) )
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
            if ( !Scope.TryGetDeclaration( identifier, out var declaration ) )
            {
                LogError( identifier, $"Identifiers references undeclared identifier '{identifier.Text}'" );
                return false;
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

            PushScope();
            if ( !TryResolveTypesInCompoundStatement( ifStatement.Body ) )
                return false;
            PopScope();

            if ( ifStatement.ElseBody != null )
            {
                PushScope();
                if ( !TryResolveTypesInCompoundStatement( ifStatement.ElseBody ) )
                    return false;
                PopScope();
            }

            return true;
        }

        private bool TryResolveTypesInForStatement( FlowScriptForStatement forStatement )
        {
            PushScope();

            if ( !TryResolveTypesInStatement( forStatement.Initializer ) )
                return false;

            if ( !TryResolveTypesInExpression( forStatement.Condition ) )
                return false;

            if ( !TryResolveTypesInExpression( forStatement.AfterLoop ) )
                return false;

            if ( !TryResolveTypesInCompoundStatement( forStatement.Body ) )
                return false;

            PopScope();

            return true;
        }

        private bool TryResolveTypesInWhileStatement( FlowScriptWhileStatement whileStatement )
        {
            PushScope();

            if ( !TryResolveTypesInExpression( whileStatement.Condition ) )
                return false;

            if ( !TryResolveTypesInCompoundStatement( whileStatement.Body ) )
                return false;

            PopScope();

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
