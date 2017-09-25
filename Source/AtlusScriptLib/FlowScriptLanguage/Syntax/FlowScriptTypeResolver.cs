using System.Collections.Generic;
using System.Diagnostics;
using AtlusScriptLib.Common.Logging;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
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
            var declarations = scanner.ScanForDeclarations( compilationUnit );
            foreach ( var declaration in declarations )
            {
                RegisterDeclaration( declaration );
            }
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
            else
            {
                mLogger.Error( $"Failed to resolve types in statement '{statement}'" );
                return false;
            }

            return true;
        }

        private bool TryResolveTypesInDeclaration( FlowScriptDeclaration declaration )
        {
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
            if ( expression.ExpressionValueType != FlowScriptValueType.Unresolved )
                return true;

            LogDebug( expression, $"Resolving expression {expression}" );

            if ( expression is FlowScriptCallExpression callExpression )
            {
                if ( !TryResolveTypesInCallExpression( callExpression ) )
                    return false;
            }
            else if ( expression is FlowScriptIdentifier identifier )
            {
                if ( !TryResolveTypesInIdentifier( identifier ) )
                    return false;
            }
            else
            {
                LogError( expression, $"Unresolved expression: {expression}" );
                return false;
            }

            LogDebug( expression, $"Resolved expression {expression} to type {expression.ExpressionValueType}" );

            return true;
        }

        private bool TryResolveTypesInCallExpression( FlowScriptCallExpression callExpression )
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
            else
            {
                LogError( identifier, "Invalid identifier. Expected function, procedure or variable identifier" );
                return false;
            }

            return true;
        }

        // Logging
        private void LogDebug( FlowScriptSyntaxNode node, string message )
        {
            mLogger.Debug( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
        }

        private void LogError( FlowScriptSyntaxNode node, string message )
        {
            mLogger.Error( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
            if ( Debugger.IsAttached )
                Debugger.Break();
        }
    }
}
