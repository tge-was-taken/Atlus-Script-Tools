﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Ast.Nodes;

namespace AtlusScriptLib.FlowScriptLanguage.Ast
{
    public class FlowScriptAstTypeResolver
    {
        private Logger mLogger;
        private Dictionary<string, FlowScriptDeclaration> mDeclaredIdentifiers;

        public FlowScriptAstTypeResolver()
        {
            mLogger = new Logger( nameof( FlowScriptAstTypeResolver ) );
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
            ScanCompilationUnitForDeclarations( compilationUnit );

            if ( !TryResolveTypesInCompilationUnit( compilationUnit ) )
                return false;

            return true;
        }

        // Declaration scanning
        private void ScanCompilationUnitForDeclarations( FlowScriptCompilationUnit compilationUnit )
        {
            ScanImportsForDeclarations( compilationUnit.Imports );
            ScanStatementsForDeclarations( compilationUnit.Statements );
        }

        private void ScanImportsForDeclarations( List<FlowScriptImport> imports )
        {

        }

        private void ScanStatementsForDeclarations( IEnumerable<FlowScriptStatement> statements )
        {
            foreach ( var statement in statements )
            {
                if ( statement is FlowScriptDeclaration declaration )
                {
                    RegisterDeclaration( declaration );

                    if ( declaration is FlowScriptProcedureDeclaration procedureDeclaration )
                    {
                        if ( procedureDeclaration.Body != null )
                            ScanStatementsForDeclarations( procedureDeclaration.Body.Statements );
                    }
                }
                else if ( statement is FlowScriptCompoundStatement compoundStatement )
                {
                    ScanStatementsForDeclarations( compoundStatement );
                }
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
        private void LogDebug( FlowScriptAstNode node, string message )
        {
            mLogger.Debug( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
        }

        private void LogError( FlowScriptAstNode node, string message )
        {
            mLogger.Error( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
            if ( Debugger.IsAttached )
                Debugger.Break();
        }
    }
}
