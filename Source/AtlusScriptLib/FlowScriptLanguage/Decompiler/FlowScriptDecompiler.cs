using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptDecompiler
    {
        private Logger mLogger;
        private FlowScript mScript;
        private FlowScriptCompilationUnit mCompilationUnit;

        // procedure state
        private FlowScriptProcedure mProcedure;
        private FlowScriptTypeIdentifier mReturnType;
        private List<FlowScriptParameter> mParameters;
        private FlowScriptCompoundStatement mBody;

        // evaluation state
        private int mEvaluatedInstructionIndex;
        private Stack<EvaluatedSyntax<FlowScriptStatement>> mEvaluationStatementStack;
        private Dictionary<int, FlowScriptFunctionDeclaration> mFunctions;
        private Dictionary<int, FlowScriptVariableDeclaration> mLocalIntVariables;
        private Dictionary<int, FlowScriptVariableDeclaration> mLocalFloatVariables;
        private Dictionary<int, FlowScriptVariableDeclaration> mStaticIntVariables;
        private Dictionary<int, FlowScriptVariableDeclaration> mStaticFloatVariables;
        private FlowScriptCallOperator mLastFunctionCall;
        private FlowScriptCallOperator mLastProcedureCall;

        // compositing state

        /// <summary>
        /// Initializes a FlowScript decompiler.
        /// </summary>
        /// <param name="version"></param>
        public FlowScriptDecompiler()
        {
            mLogger = new Logger( nameof( FlowScriptDecompiler ) );
        }

        /// <summary>
        /// Adds a decompiler log listener. Use this if you want to see what went wrong during decompilation.
        /// </summary>
        /// <param name="listener">The listener to add.</param>
        public void AddListener( LogListener listener )
        {
            listener.Subscribe( mLogger );
        }

        public bool TryDecompile( FlowScript flowScript, out FlowScriptCompilationUnit compilationUnit )
        {
            if ( !TryDecompileCompilationUnit( flowScript, out compilationUnit ))
            {
                return false;
            }

            return true;
        }

        // 
        // FlowScript Decompilation
        //
        private void InitializeCompilationUnitDecompilationState( FlowScript flowScript )
        {
            mScript = flowScript;
            mCompilationUnit = new FlowScriptCompilationUnit();
        }

        private bool TryDecompileCompilationUnit( FlowScript flowScript, out FlowScriptCompilationUnit compilationUnit )
        {
            InitializeCompilationUnitDecompilationState( flowScript );

            foreach ( var procedure in flowScript.Procedures )
            {
                if ( !TryDecompileProcedure( procedure, out var declaration ))
                {
                    compilationUnit = null;
                    return false;
                }

                mCompilationUnit.Statements.Add( declaration );
            }

            compilationUnit = mCompilationUnit;

            return true;
        }

        //
        // Procedure decompilation
        //
        private void InitializeProcedureDecompilationState( FlowScriptProcedure procedure )
        {
            mProcedure = procedure;
            mReturnType = new FlowScriptTypeIdentifier( FlowScriptValueType.Unresolved );
            mParameters = new List<FlowScriptParameter>();
            mBody = new FlowScriptCompoundStatement();
            mFunctions = new Dictionary<int, FlowScriptFunctionDeclaration>();
        }

        private bool TryDecompileProcedure( FlowScriptProcedure procedure, out FlowScriptProcedureDeclaration declaration )
        {
            InitializeProcedureDecompilationState( procedure );

            if ( !TryEvaluateInstructions( out var statements ) )
            {
                LogError( "Failed to evaluate instructions" );
                declaration = null;
                return false;
            }

            mBody = new FlowScriptCompoundStatement( statements.Select( x => x.SyntaxNode ).ToList() );
        
            declaration = new FlowScriptProcedureDeclaration(
                mReturnType,
                new FlowScriptIdentifier( FlowScriptValueType.Procedure, procedure.Name ),
                mParameters,
                mBody );

            return true;
        }

        //
        // Evaluation
        //
        private void InitializeEvaluationState()
        {
            mEvaluatedInstructionIndex = 0;
            mEvaluationStatementStack = new Stack<EvaluatedSyntax<FlowScriptStatement>>();
            mLocalIntVariables = new Dictionary<int, FlowScriptVariableDeclaration>();
            mLocalFloatVariables = new Dictionary<int, FlowScriptVariableDeclaration>();
            mStaticIntVariables = new Dictionary<int, FlowScriptVariableDeclaration>();
            mStaticFloatVariables = new Dictionary<int, FlowScriptVariableDeclaration>();

            // Add symbolic return address onto the stack
            PushStatement(
                new FlowScriptIdentifier( "<>__ReturnAddress" ) );
        }

        private bool TryEvaluateInstructions( out List<EvaluatedSyntax<FlowScriptStatement>> evaluatedStatements )
        {
            // This has so much state it might be better off being a seperate class
            InitializeEvaluationState();

            foreach ( var instruction in mProcedure.Instructions )
            {
                // Evaluate each instruction
                if ( !TryEvaluateInstruction( instruction ) )
                {
                    LogError( $"Failed to evaluate instruction: { instruction }" );
                    evaluatedStatements = null;
                    return false;
                }

                ++mEvaluatedInstructionIndex;
            }

            // Statements, yay!
            evaluatedStatements = mEvaluationStatementStack.ToList();
            evaluatedStatements.Reverse();

            // Insert label declarations
            foreach ( var label in mProcedure.Labels )
            {
                // Simple binary search
                int insertionIndex = -1;
                for ( int i = 0; i < evaluatedStatements.Count; i++ )
                {
                    var statement = evaluatedStatements[i];
                    if ( statement.InstructionIndex == label.InstructionIndex )
                    {
                        insertionIndex = i;
                    }
                    else if ( statement.InstructionIndex > label.InstructionIndex )
                    { 
                        if ( i > 0 )
                            insertionIndex = i - 1;
                        else
                            insertionIndex = i;
                    }
                }

                if ( insertionIndex == -1 )
                {
                    LogError( "Label is outside of instruction range" );
                    continue;
                }

                // Insert label declaration
                evaluatedStatements.Insert( insertionIndex,
                    new EvaluatedSyntax<FlowScriptStatement>(
                        new FlowScriptLabelDeclaration(
                            new FlowScriptIdentifier( FlowScriptValueType.Label, label.Name ) ),
                        label.InstructionIndex ) );
            }

            return true;
        }

        private bool TryEvaluateInstruction( FlowScriptInstruction instruction )
        {
            switch ( instruction.Opcode )
            {
                // Push integer to stack
                case FlowScriptOpcode.PUSHI:
                    PushStatement( new FlowScriptIntLiteral( instruction.Operand.GetInt32Value() ) );
                    break;

                // Push float to stack
                case FlowScriptOpcode.PUSHF:
                    PushStatement( new FlowScriptFloatLiteral( instruction.Operand.GetSingleValue() ) );
                    break;

                // Push value of static integer variable to stack
                case FlowScriptOpcode.PUSHIX:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !mStaticIntVariables.TryGetValue( index, out var declaration ) )
                        {
                            LogError( $"Referenced undeclared static int variable: '{index}'" );
                            return false;
                        }

                        PushStatement( declaration.Identifier );
                    }
                    break;

                // Push value of static float variable to stack
                case FlowScriptOpcode.PUSHIF:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !mStaticFloatVariables.TryGetValue( index, out var declaration ) )
                        {
                            LogError( $"Referenced undeclared static float variable: '{index}'" );
                            return false;
                        }

                        PushStatement( declaration.Identifier );
                    }
                    break;

                // Push return value of last function to stack
                case FlowScriptOpcode.PUSHREG:
                    {
                        if ( mLastFunctionCall == null )
                        {
                            LogError( $"PUSHREG before a function call!" );
                            return false;
                        }

                        PushStatement( mLastFunctionCall );
                    }
                    break;

                // Load top stack value into static integer variable
                case FlowScriptOpcode.POPIX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !mStaticIntVariables.TryGetValue( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Static, FlowScriptValueType.Int, index, true ) )
                            {
                                LogError( $"Failed to declare variable for POPIX" );
                                return false;
                            }
                        }
                        else
                        {
                            if ( !TryPopExpression( out var value ) )
                            {
                                LogError( $"Failed to pop expression for variable assignment" );
                                return false;
                            }

                            PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        }
                    }
                    break;

                // Load top stack value into static float variable
                case FlowScriptOpcode.POPFX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !mStaticFloatVariables.TryGetValue( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Static, FlowScriptValueType.Float, index, true ) )
                            {
                                LogError( $"Failed to declare variable for POPIX" );
                                return false;
                            }
                        }
                        else
                        {
                            if ( !TryPopExpression( out var value ) )
                            {
                                LogError( $"Failed to pop expression for variable assignment" );
                                return false;
                            }

                            PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        }
                    }
                    break;

                // Marker for a procedure start
                // Doesn't really do anything 
                case FlowScriptOpcode.PROC:
                    break;

                // Call to function
                case FlowScriptOpcode.COMM:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !mFunctions.TryGetValue( index, out var function ) )
                        {
                            LogError( $"Referenced unknown function: '{index}'" );
                            return false;
                        }

                        var arguments = new List<FlowScriptExpression>();
                        foreach ( var parameter in function.Parameters )
                        {
                            if ( !TryPopExpression( out var argument ) )
                            {
                                return false;
                            }

                            arguments.Add( argument );
                        }

                        var callOperator = new FlowScriptCallOperator( function.Identifier, arguments );
                        PushStatement( callOperator );
                        mLastFunctionCall = callOperator;
                    }
                    break;

                // End of procedure
                // Jumps to value on stack
                case FlowScriptOpcode.END:
                    {
                        // Todo: return value
                        PushStatement( new FlowScriptReturnStatement() );
                    }
                    break;

                // Jump to procedure
                // without saving return address
                case FlowScriptOpcode.JUMP:
                    {
                        // Todo
                        LogError( "Todo: JUMP" );
                        return false;
                    }
                    break;

                // Call procedure
                case FlowScriptOpcode.CALL:
                    {
                        // Todo: arguments
                        var index = instruction.Operand.GetInt16Value();
                        var callOperator = new FlowScriptCallOperator( new FlowScriptIdentifier( mScript.Procedures[index].Name ) );
                        PushStatement( callOperator );
                        mLastProcedureCall = callOperator;
                    }
                    break;

                case FlowScriptOpcode.RUN:
                    {
                        // Todo:
                        LogError( "Todo: RUN" );
                        return false;
                    }
                    break;

                case FlowScriptOpcode.GOTO:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        PushStatement(
                            new FlowScriptGotoStatement(
                                new FlowScriptIdentifier( FlowScriptValueType.Label, mProcedure.Labels[index].Name ) ) );
                    }
                    break;
                case FlowScriptOpcode.ADD:
                    if ( !TryPushBinaryExpression<FlowScriptAdditionOperator>() )
                    {
                        LogError( $"Failed to evaluate ADD" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.SUB:
                    if ( !TryPushBinaryExpression<FlowScriptSubtractionOperator>() )
                    {
                        LogError( $"Failed to evaluate SUB" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.MUL:
                    if ( !TryPushBinaryExpression<FlowScriptMultiplicationOperator>() )
                    {
                        LogError( $"Failed to evaluate MUL" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.DIV:
                    if ( !TryPushBinaryExpression<FlowScriptDivisionOperator>() )
                    {
                        LogError( $"Failed to evaluate DIV" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.MINUS:
                    if ( !TryPushUnaryExpression<FlowScriptNegationOperator>() )
                    {
                        LogError( $"Failed to evaluate MINUS" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.NOT:
                    if ( !TryPushUnaryExpression<FlowScriptLogicalNotOperator>() )
                    {
                        LogError( $"Failed to evaluate NOT" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.OR:
                    if ( !TryPushBinaryExpression<FlowScriptLogicalOrOperator>() )
                    {
                        LogError( $"Failed to evaluate OR" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.AND:
                    if ( !TryPushBinaryExpression<FlowScriptLogicalAndOperator>() )
                    {
                        LogError( $"Failed to evaluate AND" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.EQ:
                    if ( !TryPushBinaryExpression<FlowScriptEqualityOperator>() )
                    {
                        LogError( $"Failed to evaluate EQ" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.NEQ:
                    if ( !TryPushBinaryExpression<FlowScriptNonEqualityOperator>() )
                    {
                        LogError( $"Failed to evaluate NEQ" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.S:
                    if ( !TryPushBinaryExpression<FlowScriptLessThanOperator>() )
                    {
                        LogError( $"Failed to evaluate S" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.L:
                    if ( !TryPushBinaryExpression<FlowScriptGreaterThanOperator>() )
                    {
                        LogError( $"Failed to evaluate L" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.SE:
                    if ( !TryPushBinaryExpression<FlowScriptLessThanOrEqualOperator>() )
                    {
                        LogError( $"Failed to evaluate SE" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.LE:
                    if ( !TryPushBinaryExpression<FlowScriptGreaterThanOrEqualOperator>() )
                    {
                        LogError( $"Failed to evaluate LE" );
                        return false;
                    }
                    break;

                // If statement
                case FlowScriptOpcode.IF:
                    {
                        // Pop condition
                        if ( !TryPopExpression( out var condition ) )
                        {
                            LogError( $"Failed to pop if condition expression" );
                            return false;
                        }

                        // The body and else body is structured later
                        PushStatement( new FlowScriptIfStatement(
                            condition,
                            null,
                            null ) );
                    }
                    break;

                // Push short
                case FlowScriptOpcode.PUSHIS:
                    PushStatement( new FlowScriptIntLiteral( instruction.Operand.GetInt16Value() ) );
                    break;

                // Push local int variable value
                case FlowScriptOpcode.PUSHLIX:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !mLocalIntVariables.TryGetValue( index, out var declaration ) )
                        {
                            LogError( $"Referenced undeclared local int variable: '{index}'" );
                            return false;
                        }

                        PushStatement( declaration.Identifier );
                    }
                    break;
                case FlowScriptOpcode.PUSHLFX:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !mLocalFloatVariables.TryGetValue( index, out var declaration ) )
                        {
                            LogError( $"Referenced undeclared local float variable: '{index}'" );
                            return false;
                        }

                        PushStatement( declaration.Identifier );
                    }
                    break;
                case FlowScriptOpcode.POPLIX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !mLocalIntVariables.TryGetValue( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Local, FlowScriptValueType.Int, index, true ) )
                            {
                                LogError( $"Failed to declare variable for POPLIX" );
                                return false;
                            }
                        }
                        else
                        {
                            if ( !TryPopExpression( out var value ) )
                            {
                                LogError( $"Failed to pop expression for variable assignment" );
                                return false;
                            }

                            PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        }
                    }
                    break;
                case FlowScriptOpcode.POPLFX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !mLocalFloatVariables.TryGetValue( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Local, FlowScriptValueType.Float, index, true ) )
                            {
                                LogError( $"Failed to declare variable for POPLFX" );
                                return false;
                            }
                        }
                        else
                        {
                            if ( !TryPopExpression( out var value ) )
                            {
                                LogError( $"Failed to pop expression for variable assignment" );
                                return false;
                            }

                            PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        }
                    }
                    break;
                case FlowScriptOpcode.PUSHSTR:
                    {
                        var stringValue = instruction.Operand.GetStringValue();
                        PushStatement( new FlowScriptStringLiteral( stringValue ) );
                    }
                    break;
                default:
                    LogError( $"Unimplemented opcode: { instruction.Opcode }" );
                    return false;
            }

            return true;
        }

        private void PushStatement( FlowScriptStatement expression )
        {
            mEvaluationStatementStack.Push( 
                new EvaluatedSyntax<FlowScriptStatement>( expression, mEvaluatedInstructionIndex ));
        }

        private bool TryPopStatement( out FlowScriptStatement statement )
        {
            if ( mEvaluationStatementStack.Count == 0 )
            {
                statement = null;
                return false;
            }

            statement = mEvaluationStatementStack.Pop().SyntaxNode;
            return true;
        }

        private bool TryPopExpression( out FlowScriptExpression expression )
        {
            if ( !TryPopStatement( out var statement ))
            {
                expression = null;
                return false;
            }

            expression = statement as FlowScriptExpression;
            return expression != null;
        }

        private bool TryPushBinaryExpression<T>() where T : FlowScriptBinaryExpression, new()
        {
            var binaryExpression = new T();
            if ( !TryPopExpression( out var left ) )
            {
                return false;
            }

            if ( !TryPopExpression( out var right ) )
            {
                return false;
            }

            binaryExpression.Left = left;
            binaryExpression.Right = right;

            PushStatement( binaryExpression );
            return true;
        }

        private bool TryPushUnaryExpression<T>() where T : FlowScriptUnaryExpression, new()
        {
            var uanryExpression = new T();
            if ( !TryPopExpression( out var operand ) )
            {
                return false;
            }

            uanryExpression.Operand = operand;

            PushStatement( uanryExpression );
            return true;
        }

        private bool TryDeclareVariable( FlowScriptModifierType modifierType, FlowScriptValueType valueType, short index, bool hasInitializer )
        {
            var modifier = new FlowScriptVariableModifier( modifierType );
            var type = new FlowScriptTypeIdentifier( valueType );
            var identifier = new FlowScriptIdentifier( valueType, GenerateVariableName( modifierType, valueType, index ) );

            FlowScriptExpression initializer = null;
            if ( hasInitializer )
            {
                if ( !TryPopExpression( out initializer ))
                {
                    LogError( $"Attempted to declare variable {identifier} with initializer, but expression stack is empty!" );
                    return false;
                }
            }

            var variableDeclaration = new FlowScriptVariableDeclaration( modifier, type, identifier, initializer );

            switch ( modifierType )
            {
                case FlowScriptModifierType.Local:
                    switch ( valueType )
                    {
                        case FlowScriptValueType.Int:
                            if ( mLocalIntVariables.ContainsKey( index ) )
                            {
                                LogError( $"Attempted to declare already declared local int variable: '{index}'" );
                                return false;
                            }

                            mLocalIntVariables[index] = variableDeclaration;
                            break;
                        case FlowScriptValueType.Float:
                            if ( mLocalFloatVariables.ContainsKey( index ) )
                            {
                                LogError( $"Attempted to declare already declared local float variable: '{index}'" );
                                return false;
                            }

                            mLocalFloatVariables[index] = variableDeclaration;
                            break;
                        default:
                            LogError( $"Variable type not implemented: { type }" );
                            return false;
                    }
                    break;
                case FlowScriptModifierType.Static:
                    switch ( valueType )
                    {
                        case FlowScriptValueType.Int:
                            if ( mStaticIntVariables.ContainsKey( index ))
                            {
                                LogError( $"Attempted to declare already declared static int variable: '{index}'" );
                                return false;
                            }

                            mStaticIntVariables[index] = variableDeclaration;
                            break;
                        case FlowScriptValueType.Float:

                            if ( mStaticFloatVariables.ContainsKey( index ) )
                            {
                                LogError( $"Attempted to declare already declared static float variable: '{index}'" );
                                return false;
                            }

                            mStaticFloatVariables[index] = variableDeclaration;
                            break;
                        default:
                            LogError( $"Variable value type not implemented: { valueType }" );
                            return false;
                    }
                    break;
                default:
                    LogError( $"Variable modifier type not implemented: { modifierType }" );
                    return false;
            }

            PushStatement( variableDeclaration );

            return true;
        }

        private string GenerateVariableName( FlowScriptModifierType modifier, FlowScriptValueType type, short index )
        {
            switch ( modifier )
            {
                case FlowScriptModifierType.Local:
                    return $"variable{index}";
                case FlowScriptModifierType.Static:
                    return $"sVariable{index}";
            }

            Debug.Assert( false );
            return null;
        }

        //
        // Compositing
        //
        private void InitializeCompositionState()
        {
        }

        private bool TryCompositeEvaluatedInstructions( List<EvaluatedSyntax<FlowScriptStatement>> evaluatedStatements )
        {
            return true;
        }

        //
        // Logging
        //
        private void LogInfo( string message )
        {
            mLogger.Info( $"            {message}" );
        }

        private void LogError( string message )
        {
            mLogger.Error( $"            {message}" );

            if ( Debugger.IsAttached )
            {
                Debugger.Break();
            }
        }

        class EvaluatedSyntax<T> where T : FlowScriptSyntaxNode
        {
            public T SyntaxNode { get; set; }

            public int InstructionIndex { get; set; }

            public EvaluatedSyntax( T syntaxNode, int instructionIndex )
            {
                SyntaxNode = syntaxNode;
                InstructionIndex = instructionIndex;
            }

            public override string ToString()
            {
                return $"{SyntaxNode} at {InstructionIndex}";
            }
        }
    }
}
