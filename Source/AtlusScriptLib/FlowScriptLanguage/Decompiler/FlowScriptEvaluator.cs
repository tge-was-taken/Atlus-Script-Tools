using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.FunctionDatabase;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    internal class FlowScriptProcedurePreEvaluationInfo
    {
        public FlowScriptProcedure Procedure { get; set; }

        public List<FlowScriptStackSnapshot> Snapshots { get; set; }
    }

    internal class FlowScriptStackSnapshot
    {
        public Stack<FlowScriptStackValueType> Stack { get; set; }

        public int StackBalance { get; set; }
    }

    internal enum FlowScriptStackValueType
    {
        None,
        Int,
        Float,
        String,
        Return
    }

    public class FlowScriptEvaluator
    {
        private readonly Logger mLogger;

        // FlowScript evaluation
        private FlowScript mScript;
        private Dictionary<int, FlowScriptFunctionDeclaration> mFunctions;
        private Dictionary<int, FlowScriptProcedureDeclaration> mProcedures;
        private Stack<FlowScriptEvaluatedScope> mScopeStack;
        private FlowScriptEvaluatedScope Scope => mScopeStack.Peek();

        // Procedure evaluation
        private FlowScriptProcedure mProcedure;
        private List<FlowScriptInstruction> mInstructions;
        private int mEvaluatedInstructionIndex;
        private int mRealStackCount;
        private Stack<FlowScriptEvaluatedStatement> mEvaluationStatementStack;
        private Stack<FlowScriptEvaluatedStatement> mExpressionStack;
        private FlowScriptCallOperator mLastFunctionCall;
        private FlowScriptCallOperator mLastProcedureCall;
        private FlowScriptValueType mReturnType;
        private List<FlowScriptParameter> mParameters;
        private List<FlowScriptEvaluatedIdentifierReference> mProcedureLocalVariables;

        public IFunctionDatabase FunctionDatabase { get; set; }

        public FlowScriptEvaluator()
        {
            mLogger = new Logger( nameof( FlowScriptEvaluator ) );
        }

        /// <summary>
        /// Adds a decompiler log listener. Use this if you want to see what went wrong during decompilation.
        /// </summary>
        /// <param name="listener">The listener to add.</param>
        public void AddListener( LogListener listener )
        {
            listener.Subscribe( mLogger );
        }

        //
        // FlowScript evaluation
        //
        public bool TryEvaluateScript( FlowScript flowScript, out FlowScriptEvaluationResult result )
        {
            InitializeScriptEvaluationState( flowScript );

            PushScope();

            // Register functions used in the script
            if ( !TryRegisterUsedFunctions() )
            {
                LogError( "Failed to register functions" );
                result = null;
                return false;
            }

            // Register top level variables
            RegisterTopLevelVariables();

            // Start building result
            result = new FlowScriptEvaluationResult( flowScript, Scope );
            result.Functions.AddRange( mFunctions.Values );

            // Pre-evaluating stuff
            var infos = PreEvaluateProcedures( flowScript );
            var problematicInfos = infos.Where( x => x.Snapshots.Any( y => y.StackBalance < 1 ) );

            // Evaluate procedures
            foreach ( var procedure in flowScript.Procedures )
            {
                if ( !TryEvaluateProcedure( procedure, out var evaluatedProcedure ) )
                {
                    result = null;
                    return false;
                }

                result.Procedures.Add( evaluatedProcedure );
            }

            PopScope();
            return true;
        }

        private void InitializeScriptEvaluationState( FlowScript flowScript )
        {
            mScript = flowScript;
            mFunctions = new Dictionary<int, FlowScriptFunctionDeclaration>();
            mProcedures = new Dictionary< int, FlowScriptProcedureDeclaration >();
            mScopeStack = new Stack<FlowScriptEvaluatedScope>();
        }

        //
        // Declarations & scope
        //
        private void PushScope()
        {
            if ( mScopeStack.Count != 0 )
                mScopeStack.Push( new FlowScriptEvaluatedScope( Scope ) );
            else
                mScopeStack.Push( new FlowScriptEvaluatedScope( null ) );
        }

        private void PopScope()
        {
            mScopeStack.Push( mScopeStack.Pop() );
        }

        private bool TryDeclareVariable( FlowScriptModifierType modifierType, FlowScriptValueType valueType, short index, out FlowScriptVariableDeclaration declaration )
        {
            var modifier = new FlowScriptVariableModifier( modifierType );
            var type = new FlowScriptTypeIdentifier( valueType );
            var identifier = new FlowScriptIdentifier( valueType, GenerateVariableName( modifierType, valueType, index, Scope.Parent == null ) );
            declaration = new FlowScriptVariableDeclaration( modifier, type, identifier, null );

            switch ( modifierType )
            {
                case FlowScriptModifierType.Local:
                    switch ( valueType )
                    {
                        case FlowScriptValueType.Int:
                            if ( Scope.TryGetLocalIntVariable( index, out var _ ) )
                            {
                                LogError( $"Attempted to declare already declared local int variable: '{index}'" );
                                return false;
                            }

                            return Scope.TryDeclareLocalIntVariable( index, declaration );
                        case FlowScriptValueType.Float:
                            if ( Scope.TryGetLocalFloatVariable( index, out var _ ) )
                            {
                                LogError( $"Attempted to declare already declared local float variable: '{index}'" );
                                return false;
                            }

                            return Scope.TryDeclareLocalFloatVariable( index, declaration );
                        default:
                            LogError( $"Variable type not implemented: { type }" );
                            return false;
                    }
                case FlowScriptModifierType.Static:
                    switch ( valueType )
                    {
                        case FlowScriptValueType.Int:
                            if ( Scope.TryGetStaticIntVariable( index, out var _ ) )
                            {
                                LogError( $"Attempted to declare already declared static int variable: '{index}'" );
                                return false;
                            }

                            return Scope.TryDeclareStaticIntVariable( index, declaration );
                        case FlowScriptValueType.Float:

                            if ( Scope.TryGetStaticFloatVariable( index, out var _ ) )
                            {
                                LogError( $"Attempted to declare already declared static float variable: '{index}'" );
                                return false;
                            }

                            return Scope.TryDeclareStaticFloatVariable( index, declaration );
                        default:
                            LogError( $"Variable value type not implemented: { valueType }" );
                            return false;
                    }
                default:
                    LogError( $"Variable modifier type not implemented: { modifierType }" );
                    return false;
            }
        }

        private bool IsVariableDeclared( FlowScriptModifierType modifierType, FlowScriptValueType valueType, short index )
        {
            switch ( modifierType )
            {
                case FlowScriptModifierType.Local:
                    switch ( valueType )
                    {
                        case FlowScriptValueType.Int:
                            return Scope.TryGetLocalIntVariable( index, out _ );
                        case FlowScriptValueType.Float:
                            return ( Scope.TryGetLocalFloatVariable( index, out _ ) );
                    }
                    break;
                case FlowScriptModifierType.Static:
                    switch ( valueType )
                    {
                        case FlowScriptValueType.Int:
                            return Scope.TryGetStaticIntVariable( index, out _ );
                        case FlowScriptValueType.Float:
                            return Scope.TryGetStaticFloatVariable( index, out _ );
                    }
                    break;
            }

            return false;
        }

        private string GenerateVariableName( FlowScriptModifierType modifier, FlowScriptValueType type, short index, bool isTopLevel )
        {
            switch ( type )
            {
                case FlowScriptValueType.Int:
                    switch ( modifier )
                    {
                        case FlowScriptModifierType.Local:
                            return isTopLevel ? $"variable{index}" : $"localVariable{index}";
                        case FlowScriptModifierType.Static:
                            return isTopLevel ? $"sVariable{index}" : $"sLocalVariable{index}";
                    }
                    break;
                case FlowScriptValueType.Float:
                    switch ( modifier )
                    {
                        case FlowScriptModifierType.Local:
                            return isTopLevel ? $"floatVariable{index}" : $"localFloatVariable{index}";
                        case FlowScriptModifierType.Static:
                            return isTopLevel ? $"sFloatVariable{index}" : $"sLocalFloatVariable{index}";
                    }
                    break;
            }

            Debug.Assert( false );
            return null;
        }

        private string GenerateParameterName( FlowScriptValueType type, int index )
        {
            switch ( type )
            {
                case FlowScriptValueType.Int:
                    return $"param{index}";
                case FlowScriptValueType.Float:
                    return $"floatParam{index}";
            }

            Debug.Assert( false );
            return null;
        }

        private void RegisterTopLevelVariables()
        {
            var foundIntVariables = new Dictionary< int, (FlowScriptProcedure Procedure, FlowScriptModifierType Modifier, FlowScriptValueType Type) >();
            var foundFloatVariables = new Dictionary< int, (FlowScriptProcedure Procedure, FlowScriptModifierType Modifier, FlowScriptValueType Type) >();

            foreach ( var procedure in mScript.Procedures )
            {
                foreach ( var instruction in procedure.Instructions )
                {
                    var type = FlowScriptValueType.Int;
                    if ( instruction.Opcode == FlowScriptOpcode.POPFX ||
                         instruction.Opcode == FlowScriptOpcode.PUSHIF ||
                         instruction.Opcode == FlowScriptOpcode.PUSHLFX ||
                         instruction.Opcode == FlowScriptOpcode.POPLFX )
                    {
                        type = FlowScriptValueType.Float;
                    }

                    switch ( instruction.Opcode )
                    {
                        case FlowScriptOpcode.PUSHIX:
                        case FlowScriptOpcode.PUSHIF:
                        case FlowScriptOpcode.POPIX:
                        case FlowScriptOpcode.POPFX:
                        case FlowScriptOpcode.PUSHLIX:
                        case FlowScriptOpcode.PUSHLFX:
                        case FlowScriptOpcode.POPLIX:
                        case FlowScriptOpcode.POPLFX:
                            {
                                var index = instruction.Operand.GetInt16Value();
                                if ( type == FlowScriptValueType.Int && foundIntVariables.TryGetValue( index, out var context ) )
                                {
                                    // Check if it was declared in a different procedure than the one we're currently processing
                                    if ( procedure != context.Procedure )
                                    {
                                        // If the procedures are different, then this variable can't be local to the scope of the procedure
                                        if ( !IsVariableDeclared( context.Modifier, context.Type, index ) )
                                        {
                                            Debug.Assert( TryDeclareVariable( context.Modifier, context.Type, index, out _ ) );
                                        }
                                    }
                                }
                                else if ( type == FlowScriptValueType.Float && foundFloatVariables.TryGetValue( index, out context ) )
                                {
                                    // Check if it was declared in a different procedure than the one we're currently processing
                                    if ( procedure != context.Procedure )
                                    {
                                        // If the procedures are different, then this variable can't be local to the scope of the procedure
                                        if ( !IsVariableDeclared( context.Modifier, context.Type, index ) )
                                        {
                                            Debug.Assert( TryDeclareVariable( context.Modifier, context.Type, index, out _ ) );
                                        }
                                    }
                                }
                                else
                                {
                                    var modifier = FlowScriptModifierType.Static;
                                    if ( instruction.Opcode == FlowScriptOpcode.POPLIX ||
                                         instruction.Opcode == FlowScriptOpcode.PUSHLIX ||
                                         instruction.Opcode == FlowScriptOpcode.POPLFX ||
                                         instruction.Opcode == FlowScriptOpcode.PUSHLFX )
                                    {
                                        modifier = FlowScriptModifierType.Local;
                                    }

                                    if ( type == FlowScriptValueType.Int )
                                        foundIntVariables[index] = (procedure, modifier, type);
                                    else
                                        foundFloatVariables[index] = (procedure, modifier, type);
                                }

                                break;
                            }
                    }
                }
            }
        }

        private bool TryRegisterUsedFunctions()
        {
            foreach ( var instruction in mScript.Procedures.SelectMany( x => x.Instructions ).Where( x => x.Opcode == FlowScriptOpcode.COMM ) )
            {
                var index = instruction.Operand.GetInt16Value();
                if ( mFunctions.ContainsKey( index ) )
                    continue;

                // Declare function
                var function = FunctionDatabase.Functions.SingleOrDefault( x => x.Index.Value == index );

                if ( function == null )
                {
                    LogError( $"Referenced unknown function: '{index}'" );
                    return false;
                }

                mFunctions[index] = function;
            }

            return true;
        }

        // Procedure pre-evaluation
        private List<FlowScriptProcedurePreEvaluationInfo> PreEvaluateProcedures( FlowScript flowScript )
        {
            var preEvaluationInfos = new List<FlowScriptProcedurePreEvaluationInfo>();
            foreach ( var procedure in flowScript.Procedures )
            {
                var info = PreEvaluateProcedure( procedure );
                preEvaluationInfos.Add( info );
            }

            return preEvaluationInfos;
        }

        private FlowScriptProcedurePreEvaluationInfo PreEvaluateProcedure( FlowScriptProcedure procedure )
        {
            var evaluationInfo = new FlowScriptProcedurePreEvaluationInfo();
            evaluationInfo.Procedure = procedure;
            evaluationInfo.Snapshots = GetStackSnapshots( procedure );

            return evaluationInfo;
        }

        private List<FlowScriptStackSnapshot> GetStackSnapshots( FlowScriptProcedure procedure )
        {
            var snapshots = new List<FlowScriptStackSnapshot>();

            var previousSnapshot = new FlowScriptStackSnapshot();
            previousSnapshot.StackBalance = 1;
            previousSnapshot.Stack = new Stack<FlowScriptStackValueType>();
            previousSnapshot.Stack.Push( FlowScriptStackValueType.Return );

            FlowScriptFunctionDeclaration lastFunction = null;

            foreach ( var instruction in procedure.Instructions )
            {
                var snapshot = PreEvaluateInstruction( instruction, previousSnapshot, ref lastFunction );
                snapshots.Add( snapshot );
                previousSnapshot = snapshot;
            }

            return snapshots;
        }

        private FlowScriptStackSnapshot PreEvaluateInstruction( FlowScriptInstruction instruction, FlowScriptStackSnapshot previousSnapshot, ref FlowScriptFunctionDeclaration lastFunction )
        {
            var stack = new Stack<FlowScriptStackValueType>();
            foreach ( var valueType in previousSnapshot.Stack.Reverse() )
                stack.Push( valueType );

            int stackBalance = previousSnapshot.StackBalance;

            switch ( instruction.Opcode )
            {
                case FlowScriptOpcode.PUSHI:
                    stack.Push( FlowScriptStackValueType.Int );
                    ++stackBalance;
                    break;
                case FlowScriptOpcode.PUSHF:
                    stack.Push( FlowScriptStackValueType.Float );
                    ++stackBalance;
                    break;
                case FlowScriptOpcode.PUSHIX:
                    stack.Push( FlowScriptStackValueType.Int );
                    ++stackBalance;
                    break;
                case FlowScriptOpcode.PUSHIF:
                    stack.Push( FlowScriptStackValueType.Float );
                    ++stackBalance;
                    break;
                case FlowScriptOpcode.PUSHREG:
                    {
                        switch ( lastFunction.ReturnType.ValueType )
                        {
                            case FlowScriptValueType.Bool:
                            case FlowScriptValueType.Int:
                                stack.Push( FlowScriptStackValueType.Int );
                                break;
                            case FlowScriptValueType.Float:
                                stack.Push( FlowScriptStackValueType.Float );
                                break;
                        }
                        ++stackBalance;
                    }
                    break;
                case FlowScriptOpcode.POPIX:
                    if ( stack.Count != 0 )
                        stack.Pop();
                    --stackBalance;
                    break;
                case FlowScriptOpcode.POPFX:
                    if ( stack.Count != 0 )
                        stack.Pop();
                    --stackBalance;
                    break;
                case FlowScriptOpcode.PROC:
                    break;
                case FlowScriptOpcode.COMM:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        foreach ( var parameter in mFunctions[index].Parameters )
                        {
                            if ( stack.Count != 0 )
                                stack.Pop();
                            --stackBalance;
                        }

                        lastFunction = mFunctions[index];
                    }
                    break;
                case FlowScriptOpcode.END:
                    break;
                case FlowScriptOpcode.JUMP:
                    break;
                case FlowScriptOpcode.CALL:
                    break;
                case FlowScriptOpcode.RUN:
                    break;
                case FlowScriptOpcode.GOTO:
                    break;
                case FlowScriptOpcode.ADD:
                case FlowScriptOpcode.SUB:
                case FlowScriptOpcode.MUL:
                case FlowScriptOpcode.DIV:
                    {
                        if ( stack.Count != 0 )
                            stack.Pop();
                        --stackBalance;
                    }
                    break;
                case FlowScriptOpcode.MINUS:
                case FlowScriptOpcode.NOT:
                    break;
                case FlowScriptOpcode.OR:
                case FlowScriptOpcode.AND:
                case FlowScriptOpcode.EQ:
                case FlowScriptOpcode.NEQ:
                case FlowScriptOpcode.S:
                case FlowScriptOpcode.L:
                case FlowScriptOpcode.SE:
                case FlowScriptOpcode.LE:
                    {
                        if ( stack.Count != 0 )
                            stack.Pop();
                        --stackBalance;
                    }
                    break;
                case FlowScriptOpcode.IF:
                    {
                        if ( stack.Count != 0 )
                            stack.Pop();
                        --stackBalance;
                    }
                    break;
                case FlowScriptOpcode.PUSHIS:
                    stack.Push( FlowScriptStackValueType.Int );
                    ++stackBalance;
                    break;
                case FlowScriptOpcode.PUSHLIX:
                    stack.Push( FlowScriptStackValueType.Int );
                    ++stackBalance;
                    break;
                case FlowScriptOpcode.PUSHLFX:
                    stack.Push( FlowScriptStackValueType.Float );
                    ++stackBalance;
                    break;
                case FlowScriptOpcode.POPLIX:
                    if ( stack.Count != 0 )
                        stack.Pop();
                    --stackBalance;
                    break;
                case FlowScriptOpcode.POPLFX:
                    if ( stack.Count != 0 )
                        stack.Pop();
                    --stackBalance;
                    break;
                case FlowScriptOpcode.PUSHSTR:
                    stack.Push( FlowScriptStackValueType.String );
                    ++stackBalance;
                    break;
            }

            var snapshot = new FlowScriptStackSnapshot();
            snapshot.Stack = stack;
            snapshot.StackBalance = stackBalance;

            return snapshot;
        }

        //
        // Procedure evaluation
        //
        private void InitializeProcedureEvaluationState( FlowScriptProcedure procedure )
        {
            mProcedure = procedure;
            mInstructions = procedure.Instructions;
            mEvaluatedInstructionIndex = 0;
            mEvaluationStatementStack = new Stack<FlowScriptEvaluatedStatement>();
            mExpressionStack = new Stack< FlowScriptEvaluatedStatement >();
            mReturnType = FlowScriptValueType.Void;
            mParameters = new List<FlowScriptParameter>();
            mProcedureLocalVariables = new List<FlowScriptEvaluatedIdentifierReference>();

            // Add symbolic return address onto the stack
            PushStatement(
                new FlowScriptIdentifier( "<>__ReturnAddress" ) );
        }

        private bool TryEvaluateProcedure( FlowScriptProcedure procedure, out FlowScriptEvaluatedProcedure evaluatedProcedure )
        {
            // Initialize
            InitializeProcedureEvaluationState( procedure );

            // Enter procedure scope
            PushScope();

            // Evaluate instructions
            if ( !TryEvaluateInstructions() )
            {
                LogError( $"Failed to evaluate procedure '{ procedure.Name }''s instructions" );
                evaluatedProcedure = null;
                return false;
            }

            // Statements, yay!
            var evaluatedStatements = mEvaluationStatementStack.ToList();
            evaluatedStatements.Reverse();

            var first = evaluatedStatements.FirstOrDefault();
            if ( first != null && first.Statement is FlowScriptIdentifier identifier )
            {
                if ( identifier.Text == "<>__ReturnAddress" )
                    evaluatedStatements.Remove( first );
            }

            // Build result
            evaluatedProcedure = new FlowScriptEvaluatedProcedure
            {
                Procedure = procedure,
                Scope = Scope,
                Statements = evaluatedStatements,
                ReturnType = mReturnType,
                Parameters = mParameters,
                ReferencedVariables = mProcedureLocalVariables
            };

            // Exit procedure scope
            PopScope();

            return true;
        }

        //
        // Instruction evaluation
        //
        private bool TryEvaluateInstructions()
        {
            // Evaluate each instruction
            foreach ( var instruction in mProcedure.Instructions )
            {
                if ( !TryEvaluateInstruction( instruction ) )
                {
                    LogError( $"Failed to evaluate instruction: { instruction }" );
                    return false;
                }

                ++mEvaluatedInstructionIndex;
            }

            return true;
        }

        private bool TryEvaluateInstruction( FlowScriptInstruction instruction )
        {
            //LogInfo( $"Evaluating instruction: {instruction}" );
            // Todo: implement expression stack

            switch ( instruction.Opcode )
            {
                // Push integer to stack
                case FlowScriptOpcode.PUSHI:
                    PushStatement( new FlowScriptIntLiteral( instruction.Operand.GetInt32Value() ) );
                    ++mRealStackCount;
                    break;

                // Push float to stack
                case FlowScriptOpcode.PUSHF:
                    PushStatement( new FlowScriptFloatLiteral( instruction.Operand.GetSingleValue() ) );
                    ++mRealStackCount;
                    break;

                // Push value of static integer variable to stack
                case FlowScriptOpcode.PUSHIX:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !Scope.TryGetStaticIntVariable( index, out var declaration ) )
                        {
                            LogError( $"Referenced undeclared static int variable: '{index}'" );
                            //return false;

                            if ( !TryDeclareVariable( FlowScriptModifierType.Static, FlowScriptValueType.Int, index, out declaration ) )
                            {
                                LogError( "Failed to declare static int variable for PUSHIX" );
                                return false;
                            }
                        }

                        PushStatement( declaration.Identifier );
                        ++mRealStackCount;
                    }
                    break;

                // Push value of static float variable to stack
                case FlowScriptOpcode.PUSHIF:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !Scope.TryGetStaticFloatVariable( index, out var declaration ) )
                        {
                            LogError( $"Referenced undeclared static float variable: '{index}'" );
                            //return false;

                            if ( !TryDeclareVariable( FlowScriptModifierType.Static, FlowScriptValueType.Float, index, out declaration ) )
                            {
                                LogError( "Failed to declare static float variable for PUSHIF" );
                                return false;
                            }
                        }

                        PushStatement( declaration.Identifier );
                        ++mRealStackCount;
                    }
                    break;

                // Push return value of last function to stack
                case FlowScriptOpcode.PUSHREG:
                    {
                        if ( mLastFunctionCall == null )
                        {
                            LogError( "PUSHREG before a function call!" );
                            return false;
                        }

                        PushStatement( mLastFunctionCall );
                        ++mRealStackCount;
                    }
                    break;

                // Load top stack value into static integer variable
                case FlowScriptOpcode.POPIX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !Scope.TryGetStaticIntVariable( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Static, FlowScriptValueType.Int, index, out declaration ) )
                            {
                                LogError( "Failed to declare static int variable for POPIX" );
                                return false;
                            }
                        }

                        if ( !TryPopExpression( out var value ) )
                        {
                            LogError( $"Failed to pop expression for static int variable assignment" );
                            return false;
                        }

                        PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        --mRealStackCount;
                    }
                    break;

                // Load top stack value into static float variable
                case FlowScriptOpcode.POPFX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !Scope.TryGetStaticFloatVariable( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Static, FlowScriptValueType.Float, index, out declaration ) )
                            {
                                LogError( "Failed to declare static float variable for POPIX" );
                                return false;
                            }
                        }

                        if ( !TryPopExpression( out var value ) )
                        {
                            LogError( "Failed to pop expression for static float variable assignment" );
                            return false;
                        }

                        PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        --mRealStackCount;
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
                            LogError( "Unknown function: registration of functions must have failed" );
                            return false;
                        }

                        var arguments = new List<FlowScriptExpression>();
                        foreach ( var parameter in function.Parameters )
                        {
                            if ( !TryPopExpression( out var argument ) )
                            {
                                LogError( $"Failed to pop argument off stack for parameter: { parameter } of function: { function }" );
                                return false;
                            }

                            --mRealStackCount;
                            arguments.Add( argument );
                        }

                        var callOperator = new FlowScriptCallOperator( 
                            function.ReturnType.ValueType, 
                            function.Identifier,
                            arguments );

                        if ( function.ReturnType.ValueType == FlowScriptValueType.Void )
                        {
                            PushStatement( callOperator );
                        }
                        else
                        {
                            // Check if PUSHREG doesn't come next next
                            int nextCommIndex = mInstructions
                                .GetRange( mEvaluatedInstructionIndex + 1, mInstructions.Count - ( mEvaluatedInstructionIndex + 1 ) )
                                .FindIndex( x => x.Opcode == FlowScriptOpcode.COMM );

                            if ( nextCommIndex == -1 )
                                nextCommIndex = mInstructions.Count - 1;
                            else
                                nextCommIndex += mEvaluatedInstructionIndex + 1;

                            // Check if PUSHREG comes up between this and the next COMM instruction
                            // ReSharper disable once SimplifyLinqExpression
                            if ( !mInstructions.GetRange( mEvaluatedInstructionIndex, nextCommIndex - mEvaluatedInstructionIndex ).Any( x => x.Opcode == FlowScriptOpcode.PUSHREG ))
                            {
                                // If PUSHREG doesn't come before another COMM then the return value is unused
                                PushStatement( callOperator );
                            }

                            // Otherwise let PUSHREG push the call operator
                            mLastFunctionCall = callOperator;
                        }
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

                // Call procedure
                case FlowScriptOpcode.CALL:
                    {
                        // Todo: arguments
                        short index = instruction.Operand.GetInt16Value();
                        if ( index < 0 || index >= mScript.Procedures.Count )
                        {
                            LogError( $"CALL referenced invalid procedure index: {index}" );
                            return false;
                        }

                        var procedure = mScript.Procedures[index];
                        int parameterCount;
                        var arguments = new List<FlowScriptExpression>();
                        if ( mProcedures.TryGetValue( index, out var declaration ) )
                        {
                            parameterCount = declaration.Parameters.Count;
                        }
                        else
                        {
                            // Number of parameters is unknown at this time

                            //parameterCount = mRealStackCount;
                            parameterCount = 0;
                            var parameters = new List< FlowScriptParameter >();
                            for ( int i = 0; i < parameterCount; i++ )
                                parameters.Add( new FlowScriptParameter( new FlowScriptTypeIdentifier( FlowScriptValueType.Int ), new FlowScriptIdentifier( $"param{i + 1}" ) ) );

                            declaration = new FlowScriptProcedureDeclaration(
                                new FlowScriptTypeIdentifier( FlowScriptValueType.Void ),
                                new FlowScriptIdentifier( FlowScriptValueType.Procedure, procedure.Name ),
                                parameters,
                                null );

                            mProcedures[index] = declaration;
                        }
                    
                        for ( int i = 0; i < parameterCount; i++ )
                        {
                            if ( !TryPopExpression( out var expression ) )
                            {
                                LogError( "Failed to pop expression for argument" );
                                return false;
                            }

                            arguments.Add( expression );
                            --mRealStackCount;
                        }

                        var callOperator = new FlowScriptCallOperator( 
                            declaration.ReturnType.ValueType, 
                            declaration.Identifier,
                            arguments );

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

                case FlowScriptOpcode.GOTO:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        var label = mProcedure.Labels[index];
                        PushStatement(
                            new FlowScriptGotoStatement(
                                new FlowScriptIdentifier( FlowScriptValueType.Label, mProcedure.Labels[index].Name ) ),
                            label );
                    }
                    break;
                case FlowScriptOpcode.ADD:
                    if ( !TryPushBinaryExpression<FlowScriptAdditionOperator>() )
                    {
                        LogError( "Failed to evaluate ADD" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.SUB:
                    if ( !TryPushBinaryExpression<FlowScriptSubtractionOperator>() )
                    {
                        LogError( "Failed to evaluate SUB" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.MUL:
                    if ( !TryPushBinaryExpression<FlowScriptMultiplicationOperator>() )
                    {
                        LogError( "Failed to evaluate MUL" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.DIV:
                    if ( !TryPushBinaryExpression<FlowScriptDivisionOperator>() )
                    {
                        LogError( "Failed to evaluate DIV" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.MINUS:
                    if ( !TryPushUnaryExpression<FlowScriptNegationOperator>() )
                    {
                        LogError( "Failed to evaluate MINUS" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.NOT:
                    if ( !TryPushUnaryExpression<FlowScriptLogicalNotOperator>() )
                    {
                        LogError( "Failed to evaluate NOT" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.OR:
                    if ( !TryPushBinaryBooleanExpression<FlowScriptLogicalOrOperator>() )
                    {
                        LogError( "Failed to evaluate OR" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.AND:
                    if ( !TryPushBinaryBooleanExpression<FlowScriptLogicalAndOperator>() )
                    {
                        LogError( "Failed to evaluate AND" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.EQ:
                    if ( !TryPushBinaryBooleanExpression<FlowScriptEqualityOperator>() )
                    {
                        LogError( "Failed to evaluate EQ" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.NEQ:
                    if ( !TryPushBinaryBooleanExpression<FlowScriptNonEqualityOperator>() )
                    {
                        LogError( "Failed to evaluate NEQ" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.S:
                    if ( !TryPushBinaryExpression<FlowScriptLessThanOperator>() )
                    {
                        LogError( "Failed to evaluate S" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.L:
                    if ( !TryPushBinaryExpression<FlowScriptGreaterThanOperator>() )
                    {
                        LogError( "Failed to evaluate L" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.SE:
                    if ( !TryPushBinaryExpression<FlowScriptLessThanOrEqualOperator>() )
                    {
                        LogError( "Failed to evaluate SE" );
                        return false;
                    }
                    --mRealStackCount;
                    break;
                case FlowScriptOpcode.LE:
                    if ( !TryPushBinaryExpression<FlowScriptGreaterThanOrEqualOperator>() )
                    {
                        LogError( "Failed to evaluate LE" );
                        return false;
                    }
                    --mRealStackCount;
                    break;

                // If statement
                case FlowScriptOpcode.IF:
                    {
                        // Get label for when if condition is not met
                        short index = instruction.Operand.GetInt16Value();
                        var label = mProcedure.Labels[index];

                        // Pop condition
                        if ( !TryPopExpression( out var condition ) )
                        {
                            LogError( "Failed to pop if statement condition expression" );
                            return false;
                        }

                        // The body and else body is structured later
                        PushStatement( new FlowScriptIfStatement(
                            condition,
                            null,
                            null ), label );
                    }
                    --mRealStackCount;
                    break;

                // Push short
                case FlowScriptOpcode.PUSHIS:
                    PushStatement( new FlowScriptIntLiteral( instruction.Operand.GetInt16Value() ) );
                    ++mRealStackCount;
                    break;

                // Push local int variable value
                case FlowScriptOpcode.PUSHLIX:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !Scope.TryGetLocalIntVariable( index, out var declaration ) )
                        {
                            // Probably a variable declared in the root scope
                            LogInfo( $"Referenced undeclared local int variable: '{index}'" );
                            //return false;

                            if ( !TryDeclareVariable( FlowScriptModifierType.Local, FlowScriptValueType.Int, index, out declaration ) )
                            {
                                LogError( "Failed to declare local float variable for PUSHLIX" );
                                return false;
                            }
                        }

                        PushStatement( declaration.Identifier );
                        ++mRealStackCount;
                    }
                    break;
                case FlowScriptOpcode.PUSHLFX:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !Scope.TryGetLocalFloatVariable( index, out var declaration ) )
                        {
                            LogInfo( $"Referenced undeclared local float variable: '{index}'" );
                            //return false;

                            if ( !TryDeclareVariable( FlowScriptModifierType.Local, FlowScriptValueType.Float, index, out declaration ) )
                            {
                                LogError( "Failed to declare local int variable for PUSHLFX" );
                                return false;
                            }
                        }

                        PushStatement( declaration.Identifier );
                        ++mRealStackCount;
                    }
                    break;
                case FlowScriptOpcode.POPLIX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !Scope.TryGetLocalIntVariable( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Local, FlowScriptValueType.Int, index, out declaration ) )
                            {
                                LogError( "Failed to declare variable for POPLIX" );
                                return false;
                            }
                        }

                        if ( !TryPopExpression( out var value ) )
                        {
                            LogError( "Failed to pop expression for variable assignment" );
                            return false;
                        }

                        PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        --mRealStackCount;
                    }
                    break;
                case FlowScriptOpcode.POPLFX:
                    {
                        short index = instruction.Operand.GetInt16Value();

                        if ( !Scope.TryGetLocalFloatVariable( index, out var declaration ) )
                        {
                            // variable hasn't been declared yet
                            if ( !TryDeclareVariable( FlowScriptModifierType.Local, FlowScriptValueType.Float, index, out declaration ) )
                            {
                                LogError( "Failed to declare variable for POPLFX" );
                                return false;
                            }
                        }

                        if ( !TryPopExpression( out var value ) )
                        {
                            LogError( "Failed to pop expression for variable assignment" );
                            return false;
                        }

                        PushStatement( new FlowScriptAssignmentOperator( declaration.Identifier, value ) );
                        --mRealStackCount;
                    }
                    break;
                case FlowScriptOpcode.PUSHSTR:
                    {
                        var stringValue = instruction.Operand.GetStringValue();
                        PushStatement( new FlowScriptStringLiteral( stringValue ) );
                        ++mRealStackCount;
                    }
                    break;
                default:
                    LogError( $"Unimplemented opcode: { instruction.Opcode }" );
                    return false;
            }

            return true;
        }

        //
        // Evaluation stack control
        //
        private void PushStatement( FlowScriptStatement statement, FlowScriptLabel referencedLabel = null )
        {
            var visitor = new StatementVisitor( this );
            visitor.Visit( statement );

            mEvaluationStatementStack.Push(
                new FlowScriptEvaluatedStatement( statement, mEvaluatedInstructionIndex, referencedLabel ) );
        }

        private bool TryPopStatement( out FlowScriptStatement statement )
        {
            if ( mEvaluationStatementStack.Count == 0 )
            {
                statement = null;
                return false;
            }

            statement = mEvaluationStatementStack.Pop().Statement;
            return true;
        }

        private void PushExpression( FlowScriptStatement statement )
        {
            var visitor = new StatementVisitor( this );
            visitor.Visit( statement );

            mExpressionStack.Push(
                new FlowScriptEvaluatedStatement( statement, mEvaluatedInstructionIndex, null ) );
        }

        private bool TryPopExpression( out FlowScriptExpression expression )
        {
            if ( !TryPopStatement( out var statement ) )
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

        private bool TryPushBinaryBooleanExpression<T>() where T : FlowScriptBinaryExpression, new()
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

            // Check if the left expression is already returns a boolean value, and if so
            // omit the x == 0 or x == 1 expression
            if ( left.ExpressionValueType == FlowScriptValueType.Bool && right is FlowScriptIntLiteral intLiteral )
            {
                if ( intLiteral.Value == 0 ) //  x == false -> !x
                {
                    PushStatement( new FlowScriptLogicalNotOperator( left ) );
                    return true;
                }
                else if ( intLiteral.Value == 1 ) // x == true -> x
                {
                    PushStatement( left );
                    return true;
                }
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

        private class StatementVisitor : FlowScriptSyntaxVisitor
        {
            private readonly FlowScriptEvaluator mEvaluator;

            public StatementVisitor( FlowScriptEvaluator evaluator )
            {
                mEvaluator = evaluator;
            }

            public override void Visit( FlowScriptIdentifier identifier )
            {
                if ( mEvaluator.Scope.Variables.Values.Any( x => x.Identifier.Text == identifier.Text ) )
                {
                    mEvaluator.mProcedureLocalVariables.Add(
                        new FlowScriptEvaluatedIdentifierReference( identifier,
                            mEvaluator.mEvaluatedInstructionIndex ) );
                }

                base.Visit( identifier );
            }
        }
    }
}
