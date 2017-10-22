using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.FunctionDatabase;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptEvaluator
    {
        private readonly Logger mLogger;

        // FlowScript evaluation
        private FlowScript mScript;
        private Dictionary<int, FlowScriptFunctionDeclaration> mFunctions;
        private Stack<FlowScriptEvaluatedScope> mScopeStack;
        private FlowScriptEvaluatedScope Scope => mScopeStack.Peek();

        // Procedure evaluation
        private FlowScriptProcedure mProcedure;
        private int mEvaluatedInstructionIndex;
        private Stack<FlowScriptEvaluatedStatement> mEvaluationStatementStack;
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
            result = new FlowScriptEvaluationResult( Scope );
            result.Functions.AddRange( mFunctions.Values );

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

        private void RegisterTopLevelVariables()
        {
            var foundVariables = new Dictionary<int, (FlowScriptProcedure Procedure, FlowScriptModifierType Modifier, FlowScriptValueType Type)>();

            foreach ( var procedure in mScript.Procedures )
            {
                foreach ( var instruction in procedure.Instructions )
                {
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
                                if ( foundVariables.TryGetValue( index, out var context ) )
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

                                    var type = FlowScriptValueType.Int;
                                    if ( instruction.Opcode == FlowScriptOpcode.POPFX ||
                                         instruction.Opcode == FlowScriptOpcode.PUSHIF ||
                                         instruction.Opcode == FlowScriptOpcode.PUSHLFX ||
                                         instruction.Opcode == FlowScriptOpcode.POPLFX )
                                    {
                                        type = FlowScriptValueType.Float;
                                    }

                                    foundVariables[index] = (procedure, modifier, type);
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

        //
        // Procedure evaluation
        //
        private void InitializeProcedureEvaluationState( FlowScriptProcedure procedure )
        {
            mProcedure = procedure;
            mEvaluatedInstructionIndex = 0;
            mEvaluationStatementStack = new Stack<FlowScriptEvaluatedStatement>();
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
                        if ( !Scope.TryGetStaticIntVariable( index, out var declaration ) )
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
                        if ( !Scope.TryGetStaticFloatVariable( index, out var declaration ) )
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
                            LogError( "PUSHREG before a function call!" );
                            return false;
                        }

                        PushStatement( mLastFunctionCall );
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

                            arguments.Add( argument );
                        }

                        var callOperator = new FlowScriptCallOperator( function.Identifier, arguments );

                        if ( function.ReturnType.ValueType == FlowScriptValueType.Void )
                            PushStatement( callOperator );
                        else
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

                        // Number of parameters is unknown at this time
                        var callOperator = new FlowScriptCallOperator(
                            new FlowScriptIdentifier( procedure.Name ) );

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
                    break;
                case FlowScriptOpcode.SUB:
                    if ( !TryPushBinaryExpression<FlowScriptSubtractionOperator>() )
                    {
                        LogError( "Failed to evaluate SUB" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.MUL:
                    if ( !TryPushBinaryExpression<FlowScriptMultiplicationOperator>() )
                    {
                        LogError( "Failed to evaluate MUL" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.DIV:
                    if ( !TryPushBinaryExpression<FlowScriptDivisionOperator>() )
                    {
                        LogError( "Failed to evaluate DIV" );
                        return false;
                    }
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
                    if ( !TryPushBinaryExpression<FlowScriptLogicalOrOperator>() )
                    {
                        LogError( "Failed to evaluate OR" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.AND:
                    if ( !TryPushBinaryExpression<FlowScriptLogicalAndOperator>() )
                    {
                        LogError( "Failed to evaluate AND" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.EQ:
                    if ( !TryPushBinaryExpression<FlowScriptEqualityOperator>() )
                    {
                        LogError( "Failed to evaluate EQ" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.NEQ:
                    if ( !TryPushBinaryExpression<FlowScriptNonEqualityOperator>() )
                    {
                        LogError( "Failed to evaluate NEQ" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.S:
                    if ( !TryPushBinaryExpression<FlowScriptLessThanOperator>() )
                    {
                        LogError( "Failed to evaluate S" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.L:
                    if ( !TryPushBinaryExpression<FlowScriptGreaterThanOperator>() )
                    {
                        LogError( "Failed to evaluate L" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.SE:
                    if ( !TryPushBinaryExpression<FlowScriptLessThanOrEqualOperator>() )
                    {
                        LogError( "Failed to evaluate SE" );
                        return false;
                    }
                    break;
                case FlowScriptOpcode.LE:
                    if ( !TryPushBinaryExpression<FlowScriptGreaterThanOrEqualOperator>() )
                    {
                        LogError( "Failed to evaluate LE" );
                        return false;
                    }
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
                    break;

                // Push short
                case FlowScriptOpcode.PUSHIS:
                    PushStatement( new FlowScriptIntLiteral( instruction.Operand.GetInt16Value() ) );
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
                                LogError( "Failed to declare local int variable for PUSHLIX" );
                                return false;
                            }
                        }

                        PushStatement( declaration.Identifier );
                    }
                    break;
                case FlowScriptOpcode.PUSHLFX:
                    {
                        short index = instruction.Operand.GetInt16Value();
                        if ( !Scope.TryGetLocalFloatVariable( index, out var declaration ) )
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
