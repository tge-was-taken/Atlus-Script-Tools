using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler
{
    public class FlowScriptCompiler
    {
        // logger
        private Logger mLogger;

        // compiler-level state
        private FlowScriptFormatVersion mFormatVersion;
        private FlowScript mScript;
        private int mNextLabelIndex;
        private Stack<Scope> mScopeStack;
        private Scope mRootScope;
        private short mNextIntVariableIndex;
        private short mNextFloatVariableIndex;
        private int mStackValueCount = 1; // for debugging

        // procedure-level state
        private List<FlowScriptInstruction> mInstructions;
        private Dictionary<string, Label> mLabels;

        private Scope CurrentScope => mScopeStack.Peek();

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
            flowScript = null;

            if ( !TryCompileCompilationUnit( compilationUnit ) )
                return false;

            flowScript = mScript;

            return true;
        }

        private void InitializeCompilationState()
        {
            // todo: imports?
            mScript = new FlowScript( mFormatVersion );
            mNextLabelIndex = 0;
            mScopeStack = new Stack<Scope>();
            mRootScope = new Scope( null );
            mScopeStack.Push( mRootScope );
        }

        private bool TryCompileCompilationUnit( FlowScriptCompilationUnit compilationUnit )
        {
            LogInfo( compilationUnit, $"Start compiling FlowScript with version {mFormatVersion}" );

            InitializeCompilationState();
            if ( !TryRegisterDeclarationsAtRootScope( compilationUnit ) )
                return false;

            foreach ( var statement in compilationUnit.Statements )
            {
                if ( statement is FlowScriptProcedureDeclaration procedureDeclaration )
                {
                    if ( procedureDeclaration.Body != null )
                    {
                        if ( !TryCompileProcedure( procedureDeclaration, out var procedure ) )
                            return false;

                        mScript.Procedures.Add( procedure );
                    }
                }
                else if ( statement is FlowScriptVariableDeclaration variableDeclaration )
                {
                    if ( variableDeclaration.Initializer != null )
                    {
                        LogError( variableDeclaration.Initializer, "Variables declared outside of a procedure can't be initialized with a value" );
                        return false;
                    }
                }
                else if ( !( statement is FlowScriptFunctionDeclaration ) )
                {
                    LogError( statement, $"Unexpected top-level statement type: {statement}" );
                    return false;
                }
            }

            LogInfo( compilationUnit, "Done compiling compilation unit" );

            return true;
        }

        private bool TryRegisterDeclarationsAtRootScope( FlowScriptCompilationUnit compilationUnit )
        {
            LogInfo( "Registering/forward-declaring declarations at root scope." );

            // top-level only
            foreach ( var statement in compilationUnit.Statements )
            {
                if ( statement is FlowScriptFunctionDeclaration functionDeclaration )
                {
                    if ( !CurrentScope.TryDeclareFunction( functionDeclaration ) )
                    {
                        LogError( functionDeclaration, $"Failed to register function: {functionDeclaration}" );
                        return false;
                    }
                }
                else if ( statement is FlowScriptProcedureDeclaration procedureDeclaration )
                {
                    if ( !CurrentScope.TryDeclareProcedure( procedureDeclaration ) )
                    {
                        LogError( procedureDeclaration, $"Failed to register procedure: {procedureDeclaration}" );
                        return false;
                    }
                }
                else if ( statement is FlowScriptVariableDeclaration variableDeclaration )
                {
                    if ( !CurrentScope.TryDeclareVariable( variableDeclaration, mNextIntVariableIndex++ ))
                    {
                        LogError( variableDeclaration, $"Failed to register variable: {variableDeclaration}" );
                    }
                }
            }

            return true;
        }

        private void InitializeProcedureCompilationState()
        {
            mInstructions = new List<FlowScriptInstruction>();
            mLabels = new Dictionary<string, Label>();
        }

        //
        // Procedure code generation
        //
        private bool TryCompileProcedure( FlowScriptProcedureDeclaration declaration, out FlowScriptProcedure procedure )
        {
            LogInfo( declaration, $"Compiling procedure declaration: {declaration}" );

            // Initialize procedure to null so we can return without having to set it explicitly
            procedure = null;

            // Compile procedure body
            if ( !TryEmitProcedureBody( declaration ) )
                return false;

            // Create labels
            if ( !TryResolveProcedureLabels( out var labels ) )
                return false;

            // Create the procedure object
            procedure = new FlowScriptProcedure( declaration.Identifier.Text, mInstructions, labels );

            LogInfo( declaration, $"Done compiling procedure declaration: {declaration}" );

            return true;
        }

        private bool TryEmitProcedureBody( FlowScriptProcedureDeclaration declaration )
        {
            LogInfo( declaration.Body, $"Emitting procedure body for {declaration}" );

            // Initialize some state
            InitializeProcedureCompilationState();

            // Emit procedure start  
            PushScope();
            Emit( FlowScriptInstruction.PROC( mRootScope.Procedures[declaration.Identifier.Text].Index ) );

            // To mimick the official compiler
            //mNextLabelIndex++;

            // Register / forward declare labels in procedure body before codegen
            LogInfo( declaration.Body, "Forward declaring labels in procedure body" );
            if ( !TryRegisterLabels( declaration.Body ) )
            {
                LogError( declaration.Body, "Failed to forward declare labels in procedure body" );
                return false;
            }

            // Emit procedure parameters
            if ( declaration.Parameters.Count > 0 )
            {
                LogInfo( declaration, "Emitting code for procedure parameters" );
                if ( !TryEmitProcedureParameters( declaration.Parameters ) )
                {
                    LogError( declaration, "Failed to emit procedure parameters" );
                    return false;
                }
            }

            // Emit procedure body
            LogInfo( declaration.Body, "Emitting code for procedure body" );
            if ( !TryEmitCompoundStatement( declaration.Body ) )
            {
                LogError( declaration.Body, "Failed to emit procedure body" );
                return false;
            }

            // Emit procedure end
            if ( declaration.Body.Statements.Count == 0 || !( declaration.Body.Last() is FlowScriptReturnStatement ) )
            {
                LogInfo( declaration.Body, "Emitting implicit return statement" );
                Emit( FlowScriptInstruction.END() );
            }

            PopScope();

            return true;
        }

        private bool TryEmitProcedureParameters( List<FlowScriptParameter> parameters )
        {
            // Save return value
            var returnValueSave = CurrentScope.GenerateVariable( FlowScriptValueType.Int, mNextIntVariableIndex++ );
            Emit( FlowScriptInstruction.POPLIX( returnValueSave.Index ) );

            foreach ( var parameter in parameters )
            {
                if ( !TryEmitProcedureParameter( parameter ) )
                {
                    LogError( parameter, "Failed to emit code for procedure parameter" );
                    return false;
                }
            }

            // Push return value back on stack
            Emit( FlowScriptInstruction.PUSHLIX( returnValueSave.Index ) );

            return true;
        }

        private bool TryEmitProcedureParameter( FlowScriptParameter parameter )
        {
            LogInfo( parameter, $"Compiling parameter: {parameter}" );

            // Create variable declaration for parameter
            var parameterDeclaration = new FlowScriptVariableDeclaration(
                        new List<FlowScriptVariableModifier>() { new FlowScriptVariableModifier() },
                        parameter.TypeIdentifier,
                        parameter.Identifier,
                        null );

            // Emit variable declaration code
            if ( !TryEmitVariableDeclaration( parameterDeclaration ) )
                return false;

            // Snatch the variable from the current scope
            if ( !CurrentScope.TryGetVariable( parameter.Identifier.Text, out var parameterVariable ) )
                return false;

            // Assign the variable with the implicit return value on the stack
            if ( parameter.TypeIdentifier.ValueType != FlowScriptValueType.Float )
                Emit( FlowScriptInstruction.POPLIX( parameterVariable.Index ) );
            else
                Emit( FlowScriptInstruction.POPLFX( parameterVariable.Index ) );

            return true;
        }

        private bool TryRegisterLabels( FlowScriptCompoundStatement body )
        {
            foreach ( var declaration in body.Select( x => x as FlowScriptDeclaration ).Where( x => x != null ) )
            {
                if ( declaration.DeclarationType == FlowScriptDeclarationType.Label )
                {
                    mLabels[declaration.Identifier.Text] = CreateLabel( declaration.Identifier.Text );
                }
            }

            return true;
        }

        private bool TryResolveProcedureLabels( out List<FlowScriptLabel> labels )
        {
            LogInfo( "Resolving labels in procedure" );
            if ( mLabels.Values.Any( x => !x.IsResolved ) )
            {
                foreach ( var item in mLabels.Values.Where( x => !x.IsResolved ) )
                    mLogger.Error( $"Label '{item.Name}' is referenced but not declared" );

                mLogger.Error( "Failed to compile procedure because one or more undeclared labels are referenced" );
                labels = null;
                return false;
            }

            labels = mLabels.Values
                .Select( x => new FlowScriptLabel( x.Name, x.InstructionIndex ) )
                .ToList();

            mLabels.Clear();
            return true;
        }

        //
        // Statements
        //
        private bool TryEmitStatements( IEnumerable<FlowScriptStatement> statements )
        {
            foreach ( var statement in statements )
            {
                if ( !TryEmitStatement( statement ) )
                    return false;
            }

            return true;
        }

        private bool TryEmitCompoundStatement( FlowScriptCompoundStatement compoundStatement )
        {
            if ( !TryEmitStatements( compoundStatement ) )
                return false;

            return true;
        }

        private bool TryEmitStatement( FlowScriptStatement statement )
        {
            if ( statement is FlowScriptCompoundStatement compoundStatement )
            {
                if ( !TryEmitCompoundStatement( compoundStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptDeclaration declaration )
            {
                if ( statement is FlowScriptVariableDeclaration variableDeclaration )
                {
                    if ( !TryEmitVariableDeclaration( variableDeclaration ) )
                        return false;
                }
                else if ( statement is FlowScriptLabelDeclaration labelDeclaration )
                {
                    if ( !TryRegisterLabelDeclaration( labelDeclaration ) )
                        return false;
                }
                else
                {
                    LogError( statement, "Expected variable or label declaration" );
                    return false;
                }
            }
            else if ( statement is FlowScriptExpression expression )
            {
                // Hack: check if it's a single call expression to infer that we shouldn't emit a return value
                if ( statement is FlowScriptCallOperator callOperator )
                {
                    if ( !TryEmitCall( callOperator, true ) )
                        return false;
                }
                else
                {
                    if ( !TryEmitExpression( expression ) )
                        return false;
                }
            }
            else if ( statement is FlowScriptIfStatement ifStatement )
            {
                if ( !TryEmitIfStatement( ifStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptForStatement forStatement )
            {
                if ( !TryEmitForStatement( forStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptWhileStatement whileStatement )
            {
                if ( !TryEmitWhileStatement( whileStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptBreakStatement breakStatement )
            {
                if ( !TryEmitBreakStatement( breakStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptContinueStatement continueStatement )
            {
                if ( !TryEmitContinueStatement( continueStatement ) )
                    return false;
            }
            else if ( statement is FlowScriptReturnStatement returnStatement )
            {
                if ( !TryEmitReturnStatement( returnStatement ) )
                {
                    LogError( returnStatement, $"Failed to compile return statement: {returnStatement}" );
                    return false;
                }
            }
            else if ( statement is FlowScriptGotoStatement gotoStatement )
            {
                if ( !TryEmitGotoStatement( gotoStatement ) )
                {
                    LogError( gotoStatement, $"Failed to compile goto statement: {gotoStatement}" );
                    return false;
                }
            }
            else
            {
                LogError( statement, $"Compiling statement '{statement}' not implemented" );
                return false;
            }

            return true;
        }

        //
        // Variable stuff
        //
        private bool TryEmitVariableDeclaration( FlowScriptVariableDeclaration declaration )
        {
            LogInfo( declaration, $"Emitting variable declaration: {declaration}" );

            // Get variable idnex
            short variableIndex;
            if ( declaration.Type.ValueType == FlowScriptValueType.Float )
            {
                variableIndex = mNextFloatVariableIndex++;
            }
            else
            {
                variableIndex = mNextIntVariableIndex++;
            }

            // Declare variable in scope
            if ( !CurrentScope.TryDeclareVariable( declaration, variableIndex ) )
            {
                LogError( declaration, $"Variable '{declaration}' has already been declared" );
                return false;
            }

            // Emit the variable initializer if it has one         
            if ( declaration.Initializer != null )
            {
                LogInfo( declaration.Initializer, "Emitting variable initializer" );

                if ( !TryEmitVariableAssignment( declaration.Identifier, declaration.Initializer ) )
                {
                    LogError( declaration.Initializer, "Failed to emit code for variable initializer" );
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Emit variable assignment with an explicit expression.
        /// </summary>
        /// <param name="identifier"></param>
        /// <param name="expression"></param>
        /// <returns></returns>
        private bool TryEmitVariableAssignment( FlowScriptIdentifier identifier, FlowScriptExpression expression )
        {
            LogInfo( $"Emitting variable assignment: {identifier} = {expression}" );

            if ( !TryEmitExpression( expression ) )
            {
                LogError( expression, "Failed to emit code for assigment value expression" );
                return false;
            }

            if ( !TryEmitVariableAssignment( identifier ) )
            {
                LogError( identifier, "Failed to emit code for value assignment to variable" );
                return false;
            }

            return true;
        }

        /// <summary>
        /// Emit variable assignment without explicit expression.
        /// </summary>
        /// <param name="identifier"></param>
        /// <returns></returns>
        private bool TryEmitVariableAssignment( FlowScriptIdentifier identifier )
        {
            if ( !CurrentScope.TryGetVariable( identifier.Text, out var variable ) )
            {
                LogError( identifier, $"Assignment to undeclared variable: {identifier}" );
                return false;
            }

            // load the value into the variable
            if ( variable.Declaration.Type.ValueType != FlowScriptValueType.Float )
                Emit( FlowScriptInstruction.POPLIX( variable.Index ) );
            else
                Emit( FlowScriptInstruction.POPLFX( variable.Index ) );

            return true;
        }

        private bool TryRegisterLabelDeclaration( FlowScriptLabelDeclaration declaration )
        {
            LogInfo( declaration, $"Registering label declaration: {declaration}" );

            // register label
            if ( !mLabels.TryGetValue( declaration.Identifier.Text, out var label ) )
            {
                LogError( declaration.Identifier, $"Unexpected declaration of an registered label: '{declaration}'" );
                return false;
            }

            ResolveLabel( label );

            return true;
        }

        //
        // Expressions
        //
        private bool TryEmitExpression( FlowScriptExpression expression )
        {
            if ( expression is FlowScriptCallOperator callExpression )
            {
                if ( !TryEmitCall( callExpression ) )
                    return false;
            }
            else if ( expression is FlowScriptUnaryExpression unaryExpression )
            {
                if ( !TryEmitUnaryExpression( unaryExpression ) )
                    return false;
            }
            else if ( expression is FlowScriptBinaryExpression binaryExpression )
            {
                if ( !TryEmitBinaryExpression( binaryExpression ) )
                    return false;
            }
            else if ( expression is FlowScriptIdentifier identifier )
            {
                if ( !TryEmitPushVariableValue( identifier ) )
                    return false;
            }
            else if ( expression is FlowScriptBoolLiteral boolLiteral )
            {
                EmitPushBoolLiteral( boolLiteral );
            }
            else if ( expression is FlowScriptIntLiteral intLiteral )
            {
                EmitPushIntLiteral( intLiteral );
            }
            else if ( expression is FlowScriptFloatLiteral floatLiteral )
            {
                EmitPushFloatLiteral( floatLiteral );
            }
            else if ( expression is FlowScriptStringLiteral stringLiteral )
            {
                EmitPushStringLiteral( stringLiteral );
            }
            else
            {
                LogError( expression, $"Compiling expression '{expression}' not implemented" );
                return false;
            }

            return true;
        }

        private bool TryEmitCall( FlowScriptCallOperator callExpression, bool dontEmitReturnValue = false )
        {
            LogInfo( callExpression, $"Emitting call: {callExpression}" );

            // Compile expressions backwards so they are pushed to the stack in the right order
            LogInfo( "Emitting call arguments" );
            for ( int i = callExpression.Arguments.Count - 1; i >= 0; i-- )
            {
                if ( !TryEmitExpression( callExpression.Arguments[i] ) )
                {
                    LogError( callExpression.Arguments[i], $"Failed to compile function call argument: {callExpression.Arguments[i]}" );
                    return false;
                }
            }

            if ( mRootScope.TryGetFunction( callExpression.Identifier.Text, out var function ) )
            {
                // call function
                Emit( FlowScriptInstruction.COMM( function.Index ) );

                // push return value of function
                if ( !dontEmitReturnValue ) // part of the hack that checks if a statement is a lone call expression
                {
                    if ( function.Declaration.ReturnType.ValueType != FlowScriptValueType.Void )
                    {
                        LogInfo( callExpression, $"Emitting PUSHREG for {callExpression}" );
                        Emit( FlowScriptInstruction.PUSHREG() );
                    }
                }
            }
            else if ( mRootScope.TryGetProcedure( callExpression.Identifier.Text, out var procedure ) )
            {
                // call procedure
                Emit( FlowScriptInstruction.CALL( procedure.Index ) );

                // value will already be on the script stack so no need to push anything
            }
            else
            {
                LogError( callExpression, $"Invalid call expression. Expected function or procedure identifier, got: {callExpression.Identifier}" );
                return false;
            }

            return true;
        }

        private bool TryEmitPushVariableValue( FlowScriptIdentifier identifier )
        {
            LogInfo( identifier, $"Emitting variable reference: {identifier}" );

            if ( !CurrentScope.TryGetVariable( identifier.Text, out var variable ) )
            {
                LogError( identifier, $"Referenced undeclared variable '{identifier}'" );
                return false;
            }

            if ( variable.Declaration.Type.ValueType != FlowScriptValueType.Float )
                Emit( FlowScriptInstruction.PUSHLIX( variable.Index ) );
            else
                Emit( FlowScriptInstruction.PUSHLFX( variable.Index ) );

            return true;
        }

        private bool TryEmitUnaryExpression( FlowScriptUnaryExpression unaryExpression )
        {
            LogInfo( unaryExpression, $"Emitting unary expression: {unaryExpression}" );

            if ( !TryEmitExpression( unaryExpression.Operand ) )
            {
                LogError( unaryExpression.Operand, $"Unary expression operand failed to emit: {unaryExpression.Operand}" );
                return false;
            }

            if ( unaryExpression is FlowScriptLogicalNotOperator )
            {
                Emit( FlowScriptInstruction.NOT() );
            }
            else if ( unaryExpression is FlowScriptNegationOperator )
            {
                Emit( FlowScriptInstruction.MINUS() );
            }
            else
            {
                LogError( unaryExpression, $"Emitting unary expression '{unaryExpression}' not implemented" );
                return false;
            }

            return true;
        }

        private bool TryEmitBinaryExpression( FlowScriptBinaryExpression binaryExpression )
        {
            LogInfo( binaryExpression, $"Emitting binary expression: {binaryExpression}" );

            if ( binaryExpression is FlowScriptAssignmentOperator )
            {
                TryEmitVariableAssignment( ( ( FlowScriptIdentifier )binaryExpression.Left ), binaryExpression.Right );
            }
            else
            {
                if ( !TryEmitExpression( binaryExpression.Right ) )
                {
                    LogError( binaryExpression.Right, $"Failed to emit right expression: {binaryExpression.Left}" );
                    return false;
                }

                if ( !TryEmitExpression( binaryExpression.Left ) )
                {
                    LogError( binaryExpression.Right, $"Failed to emit left expression: {binaryExpression.Right}" );
                    return false;
                }

                if ( binaryExpression is FlowScriptAdditionOperator )
                {
                    Emit( FlowScriptInstruction.ADD() );
                }
                else if ( binaryExpression is FlowScriptSubtractionOperator )
                {
                    Emit( FlowScriptInstruction.SUB() );
                }
                else if ( binaryExpression is FlowScriptMultiplicationOperator )
                {
                    Emit( FlowScriptInstruction.MUL() );
                }
                else if ( binaryExpression is FlowScriptDivisionOperator )
                {
                    Emit( FlowScriptInstruction.DIV() );
                }
                else if ( binaryExpression is FlowScriptLogicalOrOperator )
                {
                    Emit( FlowScriptInstruction.OR() );
                }
                else if ( binaryExpression is FlowScriptLogicalAndOperator )
                {
                    Emit( FlowScriptInstruction.AND() );
                }
                else if ( binaryExpression is FlowScriptEqualityOperator )
                {
                    Emit( FlowScriptInstruction.EQ() );
                }
                else if ( binaryExpression is FlowScriptNonEqualityOperator )
                {
                    Emit( FlowScriptInstruction.NEQ() );
                }
                else if ( binaryExpression is FlowScriptLessThanOperator )
                {
                    Emit( FlowScriptInstruction.S() );
                }
                else if ( binaryExpression is FlowScriptGreaterThanOperator )
                {
                    Emit( FlowScriptInstruction.L() );
                }
                else if ( binaryExpression is FlowScriptLessThanOrEqualOperator )
                {
                    Emit( FlowScriptInstruction.SE() );
                }
                else if ( binaryExpression is FlowScriptGreaterThanOrEqualOperator )
                {
                    Emit( FlowScriptInstruction.LE() );
                }
                else
                {
                    LogError( binaryExpression, $"Emitting binary expression '{binaryExpression}' not implemented" );
                    return false;
                }
            }

            return true;
        }

        //
        // Literal values
        //
        private void EmitPushBoolLiteral( FlowScriptBoolLiteral boolLiteral )
        {
            if ( boolLiteral.Value )
                Emit( FlowScriptInstruction.PUSHIS( 1 ) );
            else
                Emit( FlowScriptInstruction.PUSHIS( 0 ) );
        }

        private void EmitPushIntLiteral( FlowScriptIntLiteral intLiteral )
        {
            if ( IntFitsInShort( intLiteral.Value ) )
                Emit( FlowScriptInstruction.PUSHIS( ( short )intLiteral.Value ) );
            else
                Emit( FlowScriptInstruction.PUSHI( intLiteral.Value ) );
        }

        private void EmitPushFloatLiteral( FlowScriptFloatLiteral floatLiteral )
        {
            Emit( FlowScriptInstruction.PUSHF( floatLiteral.Value ) );
        }

        private void EmitPushStringLiteral( FlowScriptStringLiteral stringLiteral )
        {
            Emit( FlowScriptInstruction.PUSHSTR( stringLiteral.Value ) );
        }

        private bool IntFitsInShort( int value )
        {
            return ( ( ( value & 0xffff8000 ) + 0x8000 ) & 0xffff7fff ) == 0;
        }

        // 
        // If statement
        //
        private bool TryEmitIfStatement( FlowScriptIfStatement ifStatement )
        {
            LogInfo( ifStatement, $"Emitting if statement: '{ifStatement}'" );

            // emit condition expression, which should push a boolean value to the stack
            if ( !TryEmitExpression( ifStatement.Condition ) )
            {
                LogError( ifStatement.Condition, "Failed to emit if statement condition" );
                return false;
            }

            // generate label for jump if condition is false
            var endLabel = CreateLabel( "IfEndLabel" );
            Label elseLabel = null;

            // emit if instruction that jumps to the label if the condition is false
            if ( ifStatement.ElseBody == null )
            {           
                Emit( FlowScriptInstruction.IF( endLabel.Index ) );
            }
            else
            {
                elseLabel = CreateLabel( "IfElseLabel" );
                Emit( FlowScriptInstruction.IF( elseLabel.Index ) );
            }

            // compile if body
            if ( !TryEmitIfStatementBody( ifStatement.Body, endLabel ) )
                return false;

            if ( ifStatement.ElseBody != null )
            {
                ResolveLabel( elseLabel );

                // compile if else body
                if ( !TryEmitIfStatementBody( ifStatement.ElseBody, endLabel ) )
                    return false;
            }

            ResolveLabel( endLabel );

            return true;
        }

        private bool TryEmitIfStatementBody( FlowScriptCompoundStatement body, Label endLabel )
        {
            PushScope();

            LogInfo( body, "Compiling if statement body" );
            if ( !TryEmitCompoundStatement( body ) )
            {
                LogError( body, "Failed to compile if statement body" );
                return false;
            }

            // ensure that we end up at the right position after the body
            Emit( FlowScriptInstruction.GOTO( endLabel.Index ) );
            PopScope();

            return true;
        }

        // 
        // If statement
        //
        private bool TryEmitForStatement( FlowScriptForStatement forStatement )
        {
            LogInfo( forStatement, $"Emitting for statement: '{forStatement}'" );

            // Enter for scope
            PushScope();

            // Emit initializer
            if ( !TryEmitStatement( forStatement.Initializer ) )
            {
                LogError( forStatement.Condition, "Failed to emit for statement initializer" );
                return false;
            }

            // Create labels
            var conditionLabel = CreateLabel( "ForConditionLabel" );
            var afterLoopLabel = CreateLabel( "ForAfterLoopLabel" );
            var endLabel = CreateLabel( "ForEndLabel" );

            // Emit condition check
            {
                ResolveLabel( conditionLabel );

                // Emit condition
                if ( !TryEmitExpression( forStatement.Condition ) )
                {
                    LogError( forStatement.Condition, "Failed to emit for statement condition" );
                    return false;
                }

                // Jump to the end of the loop if condition is NOT true
                Emit( FlowScriptInstruction.IF( endLabel.Index ) );
            }

            // Emit body
            {
                // Allow break & continue
                CurrentScope.BreakLabel = endLabel;
                CurrentScope.ContinueLabel = afterLoopLabel;

                // emit body
                LogInfo( forStatement.Body, "Emitting for statement body" );
                if ( !TryEmitCompoundStatement( forStatement.Body ) )
                {
                    LogError( forStatement.Body, "Failed to emit for statement body" );
                    return false;
                }
            }

            // Emit after loop
            {
                ResolveLabel( afterLoopLabel );

                if ( !TryEmitExpression( forStatement.AfterLoop ) )
                {
                    LogError( forStatement.AfterLoop, "Failed to emit for statement after loop expression" );
                    return false;
                }

                // jump to condition check
                Emit( FlowScriptInstruction.GOTO( conditionLabel.Index ) );
            }

            // We're at the end of the for loop
            ResolveLabel( endLabel );

            // Exit for scope
            PopScope();

            return true;
        }

        // 
        // While statement
        //
        private bool TryEmitWhileStatement( FlowScriptWhileStatement whileStatement )
        {
            LogInfo( whileStatement, $"Emitting while statement: '{whileStatement}'" );

            // Create labels
            var conditionLabel = CreateLabel( "WhileConditionLabel" );
            var endLabel = CreateLabel( "WhileEndLabel" );

            // Emit condition check
            {
                ResolveLabel( conditionLabel );

                // compile condition expression, which should push a boolean value to the stack
                if ( !TryEmitExpression( whileStatement.Condition ) )
                {
                    LogError( whileStatement.Condition, "Failed to emit while statement condition" );
                    return false;
                }

                // Jump to the end of the loop if condition is NOT true
                Emit( FlowScriptInstruction.IF( endLabel.Index ) );
            }

            // Emit body
            {
                // Enter while body scope
                PushScope();

                // allow break & continue
                CurrentScope.BreakLabel = endLabel;
                CurrentScope.ContinueLabel = conditionLabel;

                // emit body
                LogInfo( whileStatement.Body, "Emitting while statement body" );
                if ( !TryEmitCompoundStatement( whileStatement.Body ) )
                {
                    LogError( whileStatement.Body, "Failed to emit while statement body" );
                    return false;
                }

                // jump to condition check
                Emit( FlowScriptInstruction.GOTO( conditionLabel.Index ) );

                // Exit while body scope
                PopScope();
            }

            // We're at the end of the while loop
            ResolveLabel( endLabel );

            return true;
        }

        //
        // Control statements
        //
        private bool TryEmitBreakStatement( FlowScriptBreakStatement breakStatement )
        {
            if ( !CurrentScope.TryGetBreakLabel( out var label ) )
            {
                LogError( breakStatement, "Break statement is invalid in this context" );
                return false;
            }

            Emit( FlowScriptInstruction.GOTO( label.Index ) );

            return true;
        }

        private bool TryEmitContinueStatement( FlowScriptContinueStatement continueStatement )
        {
            if ( !CurrentScope.TryGetContinueLabel( out var label ) )
            {
                LogError( continueStatement, "Continue statement is invalid in this context" );
                return false;
            }

            Emit( FlowScriptInstruction.GOTO( label.Index ) );

            return true;
        }

        private bool TryEmitReturnStatement( FlowScriptReturnStatement returnStatement )
        {
            LogInfo( returnStatement, $"Emitting return statement: '{returnStatement}'" );

            if ( returnStatement.Value != null )
            {
                // Save return address in a temporary variable
                var returnAddressSave = CurrentScope.GenerateVariable( FlowScriptValueType.Int, mNextIntVariableIndex++ );
                Emit( FlowScriptInstruction.POPLIX( returnAddressSave.Index ) );

                // Emit return value
                if ( !TryEmitExpression( returnStatement.Value ) )
                {
                    LogError( returnStatement.Value, $"Failed to emit return value: {returnStatement.Value}" );
                    return false;
                }

                // Pop saved return address back on the stack
                Emit( FlowScriptInstruction.PUSHLIX( returnAddressSave.Index ) );
            }

            // emit end
            Emit( FlowScriptInstruction.END() );
            return true;
        }

        private bool TryEmitGotoStatement( FlowScriptGotoStatement gotoStatement )
        {
            LogInfo( gotoStatement, $"Emitting goto statement: '{gotoStatement}'" );

            if ( !mLabels.TryGetValue( gotoStatement.LabelIdentifier.Text, out var label ) )
            {
                LogError( gotoStatement.LabelIdentifier, $"Goto statement referenced undeclared label: {gotoStatement.LabelIdentifier}" );
                return false;
            }

            // emit goto
            Emit( FlowScriptInstruction.GOTO( label.Index ) );
            return true;
        }

        // Helpers
        private void Emit( FlowScriptInstruction instruction )
        {
            mInstructions.Add( instruction );

            /*
            switch ( instruction.Opcode )
            {
                case FlowScriptOpcode.PUSHI:
                case FlowScriptOpcode.PUSHF:
                case FlowScriptOpcode.PUSHIX:
                case FlowScriptOpcode.PUSHIF:
                case FlowScriptOpcode.PUSHREG:
                    ++mStackValueCount;
                    break;
                case FlowScriptOpcode.POPIX:
                case FlowScriptOpcode.POPFX:
                    --mStackValueCount;
                    break;
                case FlowScriptOpcode.END:
                    {
                        // Log stack value count at procedure end
                        mLogger.Debug( $"{mStackValueCount} values on stack at end" );

                        if ( mStackValueCount != 1 )
                        {
                            mLogger.Debug( "More or less than 1 value on the stack. Return address might be corrupted if this is not a leaf function." );
                        }

                        if ( mStackValueCount > 0 )
                            --mStackValueCount;
                    }
                    break;
                case FlowScriptOpcode.ADD:
                case FlowScriptOpcode.SUB:
                case FlowScriptOpcode.MUL:
                case FlowScriptOpcode.DIV:
                    --mStackValueCount;
                    break;
                case FlowScriptOpcode.EQ:
                case FlowScriptOpcode.NEQ:
                case FlowScriptOpcode.S:
                case FlowScriptOpcode.L:
                case FlowScriptOpcode.SE:
                case FlowScriptOpcode.LE:
                case FlowScriptOpcode.IF:
                    --mStackValueCount;
                    break;
                case FlowScriptOpcode.PUSHIS:
                case FlowScriptOpcode.PUSHLIX:
                case FlowScriptOpcode.PUSHLFX:
                    ++mStackValueCount;
                    break;
                case FlowScriptOpcode.POPLIX:
                case FlowScriptOpcode.POPLFX:
                    --mStackValueCount;
                    break;
                case FlowScriptOpcode.PUSHSTR:
                    ++mStackValueCount;
                    break;
                case FlowScriptOpcode.CALL:
                    ++mStackValueCount;
                    break;
                case FlowScriptOpcode.COMM:
                    mStackValueCount -= mRootScope.Functions.Values.Single( x => x.Index == instruction.Operand.GetInt16Value() ).Declaration.Parameters.Count;
                    break;
            }
            */
        }

        private Label CreateLabel( string name )
        {
            var label = new Label();
            label.Index = ( short )mLabels.Count;
            label.Name = name + "_" + mNextLabelIndex++;

            mLabels.Add( label.Name, label );

            return label;
        }

        private void ResolveLabel( Label label )
        {
            label.InstructionIndex = ( short )( mInstructions.Count );
            label.IsResolved = true;

            LogInfo( $"Resolved label {label.Name} to instruction index {label.InstructionIndex}" );
        }

        private void PushScope()
        {
            mScopeStack.Push( new Scope( mScopeStack.Peek() ) );
            LogInfo( "Entered scope" );
        }

        private void PopScope()
        {
            mScopeStack.Pop();
            LogInfo( "Exited scope" );
        }

        //
        // Logging
        //
        private void LogInfo( FlowScriptSyntaxNode node, string message )
        {
            if ( node.SourceInfo != null )
                mLogger.Info( $"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}" );
            else
                LogInfo( message );
        }

        private void LogInfo( string message )
        {
            mLogger.Info( $"            {message}" );
        }

        private void LogError( FlowScriptSyntaxNode node, string message )
        {
            if ( node.SourceInfo != null )
                mLogger.Error( $"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}" );
            else
                LogError( message );

            if ( Debugger.IsAttached )
                Debugger.Break();
        }

        private void LogError( string message )
        {
            mLogger.Error( $"            {message}" );
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

        class Label
        {
            public string Name { get; set; }

            public short Index { get; set; }

            public short InstructionIndex { get; set; }

            public bool IsResolved { get; set; }
        }

        class Scope
        {
            public Scope Parent { get; set; }

            public Dictionary<string, Function> Functions { get; set; }

            public Dictionary<string, Procedure> Procedures { get; set; }

            public Dictionary<string, Variable> Variables { get; set; }

            public Label BreakLabel { get; set; }

            public Label ContinueLabel { get; set; }

            public Scope( Scope parent )
            {
                Parent = parent;
                Functions = new Dictionary<string, Function>();
                Procedures = new Dictionary<string, Procedure>();
                Variables = new Dictionary<string, Variable>();
            }

            public bool TryGetBreakLabel( out Label label )
            {
                if ( BreakLabel != null )
                {
                    label = BreakLabel;
                    return true;
                }

                if ( Parent != null )
                    return Parent.TryGetBreakLabel( out label );

                label = null;
                return false;
            }

            public bool TryGetContinueLabel( out Label label )
            {
                if ( ContinueLabel != null )
                {
                    label = ContinueLabel;
                    return true;
                }

                if ( Parent != null )
                    return Parent.TryGetContinueLabel( out label );

                label = null;
                return false;
            }

            public bool TryGetFunction( string name, out Function function )
            {
                if ( !Functions.TryGetValue( name, out function ) )
                {
                    if ( Parent == null )
                        return false;

                    if ( !Parent.TryGetFunction( name, out function ) )
                        return false;
                }

                return true;
            }

            public bool TryGetProcedure( string name, out Procedure procedure )
            {
                if ( !Procedures.TryGetValue( name, out procedure ) )
                {
                    if ( Parent == null )
                        return false;

                    if ( !Parent.TryGetProcedure( name, out procedure ) )
                        return false;
                }

                return true;
            }

            public bool TryGetVariable( string name, out Variable variable )
            {
                if ( !Variables.TryGetValue( name, out variable ) )
                {
                    if ( Parent == null )
                        return false;

                    if ( !Parent.TryGetVariable( name, out variable ) )
                        return false;
                }

                return true;
            }

            public bool TryDeclareFunction( FlowScriptFunctionDeclaration declaration )
            {
                if ( TryGetFunction( declaration.Identifier.Text, out _ ) )
                    return false;

                var function = new Function();
                function.Declaration = declaration;
                function.Index = ( short )declaration.Index.Value;

                Functions[declaration.Identifier.Text] = function;

                return true;
            }

            public bool TryDeclareProcedure( FlowScriptProcedureDeclaration declaration )
            {
                if ( TryGetProcedure( declaration.Identifier.Text, out _ ) )
                    return false;

                var procedure = new Procedure();
                procedure.Declaration = declaration;
                procedure.Index = ( short )Procedures.Count;

                Procedures[declaration.Identifier.Text] = procedure;

                return true;
            }

            public bool TryDeclareVariable( FlowScriptVariableDeclaration declaration, short index )
            {
                if ( TryGetVariable( declaration.Identifier.Text, out _ ) )
                    return false;

                var variable = new Variable();
                variable.Declaration = declaration;
                variable.Index = index;

                Variables[declaration.Identifier.Text] = variable;

                return true;
            }

            public Variable GenerateVariable( FlowScriptValueType type, short index )
            {
                var declaration = new FlowScriptVariableDeclaration(
                    new List<FlowScriptVariableModifier>() { new FlowScriptVariableModifier() },
                    new FlowScriptTypeIdentifier( type ),
                    new FlowScriptIdentifier( type, $"<>__generatedVariable{index}" ),
                    null );

                Debug.Assert( TryDeclareVariable( declaration, index ) );
                Debug.Assert( TryGetVariable( declaration.Identifier.Text, out var variable ) );

                return variable;
            }
        }
    }
}
