using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler
{
    public class FlowScriptCompiler
    {
        private Logger mLogger;
        private FlowScriptFormatVersion mFormatVersion;
        private FlowScript mScript;

        private Dictionary<string, Function> mFunctions;
        private Dictionary<string, Procedure> mProcedures;
        private Dictionary<string, Variable> mVariables;

        public FlowScriptCompiler( FlowScriptFormatVersion version )
        {
            mLogger = new Logger( nameof( FlowScriptCompiler ) );
            mFormatVersion = version;
        }

        /// <summary>
        /// Adds a compiler log listener. Use this if you want to see what went wrong during compilation.
        /// </summary>
        /// <param name="listener">The listener to add.</param>
        public void AddListener( LogListener listener )
        {
            listener.Subscribe( mLogger );
        }

        public bool TryCompile( FlowScriptCompilationUnit compilationUnit, out FlowScript flowScript )
        {
            LogDebug( compilationUnit, $"Start compiling FlowScript with version {mFormatVersion}" );

            flowScript = null;

            if ( !TryCompileCompilationUnit( compilationUnit ))
                return false;

            flowScript = mScript;

            return true;
        }

        private bool TryCompileCompilationUnit( FlowScriptCompilationUnit compilationUnit )
        {
            // todo: imports?
            mScript = new FlowScript( mFormatVersion );
            mFunctions = new Dictionary<string, Function>();
            mProcedures = new Dictionary<string, Procedure>();
            mVariables = new Dictionary<string, Variable>();

            foreach ( var statement in compilationUnit.Statements )
            {
                if ( statement is FlowScriptFunctionDeclaration functionDeclaration )
                {
                    RegisterFunction( functionDeclaration );
                }
                else if ( statement is FlowScriptProcedureDeclaration procedureDeclaration )
                {
                    if ( procedureDeclaration.Body != null )
                    {
                        if ( !TryCompileProcedureDeclaration( procedureDeclaration, out var procedure ) )
                            return false;

                        mScript.Procedures.Add( procedure );
                    }
                }
            }

            return true;
        }

        private bool TryCompileProcedureDeclaration( FlowScriptProcedureDeclaration procedureDeclaration, out FlowScriptProcedure procedure )
        {
            procedure = new FlowScriptProcedure( procedureDeclaration.Identifier.Text );

            // Compile procedure body
            if ( !TryCompileStatements( procedureDeclaration.Body, procedure.Instructions ) )
                return false;

            // End procedure
            procedure.Instructions.Add( FlowScriptInstruction.END() );

            return true;
        }

        private bool TryCompileStatements( IEnumerable<FlowScriptStatement> statements, List<FlowScriptInstruction> instructions )
        {
            foreach ( var statement in statements )
            {
                if ( statement is FlowScriptCompoundStatement compoundStatement )
                {
                    if ( !TryCompileStatements( compoundStatement, instructions ) )
                        return false;
                }
                else if ( statement is FlowScriptDeclaration declaration )
                {
                    if ( declaration.DeclarationType != FlowScriptDeclarationType.Variable )
                    {
                        LogError( declaration, "Expected variable declaration" );
                        return false;
                    }

                    if ( !TryCompileVariableDeclaration( ( FlowScriptVariableDeclaration )declaration, instructions ) )
                        return false;
                }
                else if ( statement is FlowScriptExpression expression )
                {
                    if ( !TryCompileExpression( expression, instructions ) )
                        return false;
                }
                else
                {
                    LogError( statement, $"Compiling statement '{statement}' not implemented" );
                    return false;
                }
            }

            return true;
        }

        private bool TryCompileVariableDeclaration( FlowScriptVariableDeclaration declaration, List<FlowScriptInstruction> instructions )
        {
            // register variable
            RegisterVariable( declaration );

            // compile the initializer if it has one
            if ( declaration.Initializer != null )
            {
                if ( !TryCompileExpression( declaration.Initializer, instructions ) )
                    return false;

                // load the value into the variable
                instructions.Add( FlowScriptInstruction.POPLIX( mVariables[declaration.Identifier.Text].Index ) );
            }

            return true;
        }

        private bool TryCompileExpression( FlowScriptExpression expression, List<FlowScriptInstruction> instructions )
        {
            if ( expression is FlowScriptCallExpression callExpression )
            {
                if ( !TryCompileFunctionOrProcedureCall( callExpression, instructions ) )
                    return false;
            }
            else if ( expression is FlowScriptIdentifier identifier )
            {
                if ( !TryCompilePushVariableValue( identifier, instructions ) )
                    return false;
            }
            else if ( expression is FlowScriptBoolLiteral boolLiteral )
            {
                CompilePushBoolLiteral( boolLiteral, instructions );
            }
            else if ( expression is FlowScriptIntLiteral intLiteral )
            {
                CompilePushIntLiteral( intLiteral, instructions );
            }
            else if ( expression is FlowScriptFloatLiteral floatLiteral )
            {
                CompilePushFloatLiteral( floatLiteral, instructions );
            }
            else if ( expression is FlowScriptStringLiteral stringLiteral )
            {
                CompilePushStringLiteral( stringLiteral, instructions );
            }
            else
            {
                LogError( expression, $"Compiling expression '{expression}' not implemented" );
                return false;
            }

            return true;
        }

        private bool TryCompileFunctionOrProcedureCall( FlowScriptCallExpression callExpression, List<FlowScriptInstruction> instructions )
        {
            for ( int i = callExpression.Arguments.Count - 1; i >= 0; i-- )
            {
                if ( !TryCompileExpression( callExpression.Arguments[i], instructions ) )
                    return false;
            }

            if ( mFunctions.TryGetValue(callExpression.Identifier.Text, out var function))
            {
                // call function
                instructions.Add( FlowScriptInstruction.COMM( function.Index ) );

                // push return value of fucntion
                if ( function.Declaration.ReturnType.ValueType != FlowScriptValueType.Void )
                    instructions.Add( FlowScriptInstruction.PUSHREG() );
            }
            else if ( mProcedures.TryGetValue( callExpression.Identifier.Text, out var procedure ) )
            {
                // call procedure
                instructions.Add( FlowScriptInstruction.CALL( function.Index ) );

                // value will already be on the script stack so no need to push anything
            }
            else
            {
                LogError( callExpression, "Invalid call expression. Expected function or procedure identifier" );
                return false;
            }

            return true;
        }

        private bool TryCompilePushVariableValue( FlowScriptIdentifier identifier, List<FlowScriptInstruction> instructions )
        {
            if ( !mVariables.TryGetValue( identifier.Text, out var variable ) )
            {
                LogError( identifier, $"Referenced undeclared variable '{identifier}'" );
                return false;
            }

            if ( variable.Declaration.Type.ValueType == FlowScriptValueType.Bool || variable.Declaration.Type.ValueType == FlowScriptValueType.Int )
            {
                instructions.Add( FlowScriptInstruction.PUSHLIX( variable.Index ) );
            }
            else if ( variable.Declaration.Type.ValueType == FlowScriptValueType.Float )
            {
                instructions.Add( FlowScriptInstruction.PUSHLFX( variable.Index ) );
            }
            else
            {
                LogError( identifier, $"Referenced variable {identifier} with invalid type {variable.Declaration.Type.ValueType}" );
                return false;
            }

            return true;
        }

        private void CompilePushBoolLiteral( FlowScriptBoolLiteral boolLiteral, List<FlowScriptInstruction> instructions )
        {
            if ( !boolLiteral.Value )
                instructions.Add( FlowScriptInstruction.PUSHIS( 0 ) );
            else
                instructions.Add( FlowScriptInstruction.PUSHIS( 1 ) );
        }

        private void CompilePushIntLiteral( FlowScriptIntLiteral intLiteral, List<FlowScriptInstruction> instructions )
        {
            if ( FitsInShort( intLiteral.Value ) )
                instructions.Add( FlowScriptInstruction.PUSHIS( ( short )intLiteral.Value ) );
            else
                intLiteral.Equals( FlowScriptInstruction.PUSHI( intLiteral.Value ) );
        }

        private void CompilePushFloatLiteral( FlowScriptFloatLiteral floatLiteral, List<FlowScriptInstruction> instructions )
        {
            instructions.Add( FlowScriptInstruction.PUSHF( floatLiteral.Value ) );
        }

        private void CompilePushStringLiteral( FlowScriptStringLiteral stringLiteral, List<FlowScriptInstruction> instructions )
        {
            instructions.Add( FlowScriptInstruction.PUSHSTR( stringLiteral.Value ) );
        }

        private bool FitsInShort( int value )
        {
            return ( ( ( value & 0xffff8000 ) + 0x8000 ) & 0xffff7fff ) == 0;
        }

        private void RegisterFunction( FlowScriptFunctionDeclaration declaration )
        {
            var function = new Function();
            function.Declaration = declaration;
            function.Index = (short)declaration.Index.Value;

            mFunctions[declaration.Identifier.Text] = function;
        }

        private void RegisterProcedure( FlowScriptProcedureDeclaration declaration )
        {
            var procedure = new Procedure();
            procedure.Declaration = declaration;
            procedure.Index = (short)mProcedures.Count;

            mProcedures[declaration.Identifier.Text] = procedure;
        }

        private void RegisterVariable( FlowScriptVariableDeclaration declaration )
        {
            var variable = new Variable();
            variable.Declaration = declaration;

            if ( mVariables.Count > 0 )
            {
                variable.Index = ( short )( mVariables.Values
                    .Where( x => x.Declaration.Type.ValueType == variable.Declaration.Type.ValueType )
                    .Select( x => x.Index )
                    .Max() + 1 );
            }

            mVariables[declaration.Identifier.Text] = variable;
        }

        private void LogDebug( FlowScriptSyntaxNode node, string message )
        {
            mLogger.Debug( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
        }

        private void LogError( FlowScriptSyntaxNode node, string message )
        {
            mLogger.Error( $"{message} ({node.SourceInfo.Line}:{node.SourceInfo.Column})" );
        }

        class Function
        {
            public FlowScriptFunctionDeclaration Declaration { get; set; }

            public short Index { get; set; }
        }

        class Procedure
        {
            public FlowScriptProcedureDeclaration Declaration { get; set; }

            public short Index { get; set; }
        }

        class Variable
        {
            public FlowScriptVariableDeclaration Declaration { get; set; }

            public short Index { get; set; }
        }
    }
}
