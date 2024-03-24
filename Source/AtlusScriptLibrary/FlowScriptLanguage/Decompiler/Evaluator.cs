using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler;

internal class ProcedurePreEvaluationInfo
{
    public Procedure Procedure { get; set; }

    public List<StackSnapshot> Snapshots { get; set; }
}

internal class StackSnapshot
{
    public Stack<StackValueType> Stack { get; set; }

    public int StackBalance { get; set; }
}

internal enum StackValueType
{
    None,
    Int,
    Float,
    String,
    Return
}

public class Evaluator
{
    private readonly Logger mLogger;

    // FlowScript evaluation
    private FlowScript mScript;
    private Dictionary<int, FunctionDeclaration> mFunctions;
    private Dictionary<int, ProcedureDeclaration> mProcedures;
    private Stack<EvaluatedScope> mScopeStack;
    private EvaluatedScope Scope => mScopeStack.Peek();

    // Procedure evaluation
    private Procedure mProcedure;
    private List<Instruction> mInstructions;
    private int mEvaluatedInstructionIndex;
    private int mRealStackCount;
    private Stack<EvaluatedStatement> mEvaluationStatementStack;
    private Stack<EvaluatedStatement> mExpressionStack;
    private CallOperator mLastFunctionCall;
    private CallOperator mLastProcedureCall;
    private ValueKind mReturnKind;
    private List<Parameter> mParameters;
    private List<EvaluatedIdentifierReference> mProcedureLocalVariables;

    public Library Library { get; set; }

    public bool StrictMode { get; set; }

    public Evaluator()
    {
        mLogger = new Logger(nameof(Evaluator));
    }

    /// <summary>
    /// Adds a decompiler log listener. Use this if you want to see what went wrong during decompilation.
    /// </summary>
    /// <param name="listener">The listener to add.</param>
    public void AddListener(LogListener listener)
    {
        listener.Subscribe(mLogger);
    }

    //
    // FlowScript evaluation
    //
    public bool TryEvaluateScript(FlowScript flowScript, out EvaluationResult result)
    {
        LogInfo("Start evaluating FlowScript");
        InitializeScriptEvaluationState(flowScript);

        PushScope();

        // Register functions used in the script       
        if (!TryRegisterUsedFunctions())
        {
            LogError("Failed to register functions");
            result = null;
            return false;
        }

        // Register top level variables
        RegisterTopLevelVariables();

        // Start building result
        result = new EvaluationResult(flowScript, Scope);
        result.Functions.AddRange(mFunctions.Values);

        // Pre-evaluating stuff
        var infos = PreEvaluateProcedures(flowScript);
        var problematicInfos = infos.Where(x => x.Snapshots.Any(y => y.StackBalance < 1));

        // Evaluate procedures
        LogInfo("Evaluating procedures");
        foreach (var procedure in flowScript.Procedures)
        {
            if (!TryEvaluateProcedure(procedure, out var evaluatedProcedure))
            {
                result = null;
                return false;
            }

            result.Procedures.Add(evaluatedProcedure);
        }

        PopScope();

        LogInfo("Done evaluating FlowScript");
        return true;
    }

    private void InitializeScriptEvaluationState(FlowScript flowScript)
    {
        mScript = flowScript;
        mFunctions = new Dictionary<int, FunctionDeclaration>();
        mProcedures = new Dictionary<int, ProcedureDeclaration>();
        mScopeStack = new Stack<EvaluatedScope>();
    }

    //
    // Declarations & scope
    //
    private void PushScope()
    {
        if (mScopeStack.Count != 0)
            mScopeStack.Push(new EvaluatedScope(Scope));
        else
            mScopeStack.Push(new EvaluatedScope(null));
    }

    private void PopScope()
    {
        mScopeStack.Push(mScopeStack.Pop());
    }

    private bool TryDeclareVariable(VariableModifierKind modifierKind, ValueKind valueKind, short index, VariableIndexKind indexKind, out VariableDeclaration declaration)
    {
        var modifier = indexKind == VariableIndexKind.Implicit
            ? new VariableModifier(modifierKind)
            : new VariableModifier(modifierKind, new IntLiteral(index));

        var type = new TypeIdentifier(valueKind);
        var identifier = new Identifier(valueKind, NameFormatter.GenerateVariableName(modifierKind, valueKind, index, Scope.Parent == null));
        declaration = new VariableDeclaration(modifier, type, identifier, null);

        switch (modifierKind)
        {
            case VariableModifierKind.Local:
                switch (valueKind)
                {
                    case ValueKind.Int:
                        if (Scope.TryGetLocalIntVariable(index, out var _))
                        {
                            LogError($"Attempted to declare already declared local int variable: '{index}'");
                            return false;
                        }

                        return Scope.TryDeclareLocalIntVariable(index, declaration);
                    case ValueKind.Float:
                        if (Scope.TryGetLocalFloatVariable(index, out var _))
                        {
                            LogError($"Attempted to declare already declared local float variable: '{index}'");
                            return false;
                        }

                        return Scope.TryDeclareLocalFloatVariable(index, declaration);
                    default:
                        LogError($"Variable type not implemented: {type}");
                        return false;
                }
            case VariableModifierKind.Global:
                switch (valueKind)
                {
                    case ValueKind.Int:
                        if (Scope.TryGetGlobalIntVariable(index, out var _))
                        {
                            LogError($"Attempted to declare already declared global int variable: '{index}'");
                            return false;
                        }

                        return Scope.TryDeclareGlobalIntVariable(index, declaration);
                    case ValueKind.Float:

                        if (Scope.TryGetGlobalFloatVariable(index, out var _))
                        {
                            LogError($"Attempted to declare already declared global float variable: '{index}'");
                            return false;
                        }

                        return Scope.TryDeclareGlobalFloatVariable(index, declaration);
                    default:
                        LogError($"Variable value type not implemented: {valueKind}");
                        return false;
                }
            default:
                LogError($"Variable modifier type not implemented: {modifierKind}");
                return false;
        }
    }

    private bool IsVariableDeclared(VariableModifierKind modifierKind, ValueKind valueKind, short index)
    {
        switch (modifierKind)
        {
            case VariableModifierKind.Local:
                switch (valueKind)
                {
                    case ValueKind.Int:
                        return Scope.TryGetLocalIntVariable(index, out _);
                    case ValueKind.Float:
                        return (Scope.TryGetLocalFloatVariable(index, out _));
                }
                break;
            case VariableModifierKind.Global:
                switch (valueKind)
                {
                    case ValueKind.Int:
                        return Scope.TryGetGlobalIntVariable(index, out _);
                    case ValueKind.Float:
                        return Scope.TryGetGlobalFloatVariable(index, out _);
                }
                break;
        }

        return false;
    }

    private enum VariableIndexKind { Implicit, Explicit }

    private void RegisterTopLevelVariables()
    {
        LogInfo("Registering top level variables");

        var foundIntVariables = new Dictionary<int, (Procedure Procedure, VariableModifierKind Modifier, ValueKind Type)>();
        var foundFloatVariables = new Dictionary<int, (Procedure Procedure, VariableModifierKind Modifier, ValueKind Type)>();

        void DeclareVariableIfNotDeclared((Procedure Procedure, VariableModifierKind Modifier, ValueKind Type) context, short index, VariableIndexKind indexKind)
        {
            // If the procedures are different, then this variable can't be local to the scope of the procedure
            if (!IsVariableDeclared(context.Modifier, context.Type, index))
            {
                var result = TryDeclareVariable(context.Modifier, context.Type, index, indexKind, out _);
                Debug.Assert(result);
            }
        }

        foreach (var procedure in mScript.Procedures)
        {
            foreach (var instruction in procedure.Instructions)
            {
                var type = ValueKind.Int;
                if (instruction.Opcode == Opcode.POPFX ||
                     instruction.Opcode == Opcode.PUSHIF ||
                     instruction.Opcode == Opcode.PUSHLFX ||
                     instruction.Opcode == Opcode.POPLFX)
                {
                    type = ValueKind.Float;
                }

                switch (instruction.Opcode)
                {
                    case Opcode.PUSHIX:
                    case Opcode.PUSHIF:
                    case Opcode.POPIX:
                    case Opcode.POPFX:
                    case Opcode.PUSHLIX:
                    case Opcode.PUSHLFX:
                    case Opcode.POPLIX:
                    case Opcode.POPLFX:
                        {
                            var modifier = VariableModifierKind.Global;
                            if (instruction.Opcode == Opcode.POPLIX ||
                                 instruction.Opcode == Opcode.PUSHLIX ||
                                 instruction.Opcode == Opcode.POPLFX ||
                                 instruction.Opcode == Opcode.PUSHLFX)
                            {
                                modifier = VariableModifierKind.Local;
                            }

                            var index = instruction.Operand.Int16Value;

                            if (modifier != VariableModifierKind.Global && type == ValueKind.Int && foundIntVariables.TryGetValue(index, out var context))
                            {
                                // Check if it was declared in a different procedure than the one we're currently processing
                                if (procedure != context.Procedure)
                                {
                                    // If the procedures are different, then this variable can't be local to the scope of the procedure
                                    DeclareVariableIfNotDeclared(context, index, VariableIndexKind.Implicit);
                                }
                            }
                            else if (modifier != VariableModifierKind.Global && type == ValueKind.Float && foundFloatVariables.TryGetValue(index, out context))
                            {
                                // Check if it was declared in a different procedure than the one we're currently processing
                                if (procedure != context.Procedure)
                                {
                                    // If the procedures are different, then this variable can't be local to the scope of the procedure
                                    DeclareVariableIfNotDeclared(context, index, VariableIndexKind.Implicit);
                                }
                            }
                            else
                            {
                                context = (procedure, modifier, type);

                                if (modifier == VariableModifierKind.Global)
                                {
                                    // If it's a global, declare it anyway
                                    DeclareVariableIfNotDeclared(context, index, VariableIndexKind.Explicit);
                                }

                                if (type == ValueKind.Int)
                                    foundIntVariables[index] = context;
                                else
                                    foundFloatVariables[index] = context;
                            }

                            break;
                        }
                }
            }
        }
    }

    private bool TryRegisterUsedFunctions()
    {
        LogInfo("Registering functions");
        foreach (var instruction in mScript.Procedures.SelectMany(x => x.Instructions).Where(x => x.Opcode == Opcode.COMM))
        {
            var index = instruction.Operand.Int16Value;
            if (mFunctions.ContainsKey(index))
                continue;

            // Declare function
            var function = Library.FlowScriptModules
                                          .SelectMany(x => x.Functions)
                                          .SingleOrDefault(x => x.Index == index);

            if (function == null)
            {
                LogError($"Referenced unknown function: '{index}'");

                if (StrictMode)
                    return false;

                // Attempt to recover
                function = new FlowScriptModuleFunction()
                {
                    Index = index,
                    Name = $"UNKNOWN_FUNCTION_{index}",
                    ReturnType = "int",
                    Description = $"Unknown referenced function {index}",
                    Parameters = new List<FlowScriptModuleParameter>(),
                };
            }

            mFunctions[index] = FunctionDeclaration.FromLibraryFunction(function);
        }

        return true;
    }

    // Procedure pre-evaluation
    private List<ProcedurePreEvaluationInfo> PreEvaluateProcedures(FlowScript flowScript)
    {
        var preEvaluationInfos = new List<ProcedurePreEvaluationInfo>();
        foreach (var procedure in flowScript.Procedures)
        {
            var info = PreEvaluateProcedure(procedure);
            preEvaluationInfos.Add(info);
        }

        return preEvaluationInfos;
    }

    private ProcedurePreEvaluationInfo PreEvaluateProcedure(Procedure procedure)
    {
        var evaluationInfo = new ProcedurePreEvaluationInfo();
        evaluationInfo.Procedure = procedure;
        evaluationInfo.Snapshots = GetStackSnapshots(procedure);

        return evaluationInfo;
    }

    private List<StackSnapshot> GetStackSnapshots(Procedure procedure)
    {
        var snapshots = new List<StackSnapshot>();

        var previousSnapshot = new StackSnapshot();
        previousSnapshot.StackBalance = 1;
        previousSnapshot.Stack = new Stack<StackValueType>();
        previousSnapshot.Stack.Push(StackValueType.Return);

        FunctionDeclaration lastFunction = null;

        foreach (var instruction in procedure.Instructions)
        {
            var snapshot = PreEvaluateInstruction(instruction, previousSnapshot, ref lastFunction);
            snapshots.Add(snapshot);
            previousSnapshot = snapshot;
        }

        return snapshots;
    }

    private StackSnapshot PreEvaluateInstruction(Instruction instruction, StackSnapshot previousSnapshot, ref FunctionDeclaration lastFunction)
    {
        var stack = new Stack<StackValueType>();
        foreach (var valueType in previousSnapshot.Stack.Reverse())
            stack.Push(valueType);

        int stackBalance = previousSnapshot.StackBalance;

        switch (instruction.Opcode)
        {
            case Opcode.PUSHI:
                stack.Push(StackValueType.Int);
                ++stackBalance;
                break;
            case Opcode.PUSHF:
                stack.Push(StackValueType.Float);
                ++stackBalance;
                break;
            case Opcode.PUSHIX:
                stack.Push(StackValueType.Int);
                ++stackBalance;
                break;
            case Opcode.PUSHIF:
                stack.Push(StackValueType.Float);
                ++stackBalance;
                break;
            case Opcode.PUSHREG:
                {
                    switch (lastFunction.ReturnType.ValueKind)
                    {
                        case ValueKind.Bool:
                        case ValueKind.Int:
                            stack.Push(StackValueType.Int);
                            break;
                        case ValueKind.Float:
                            stack.Push(StackValueType.Float);
                            break;
                    }
                    ++stackBalance;
                }
                break;
            case Opcode.POPIX:
                if (stack.Count != 0)
                    stack.Pop();
                --stackBalance;
                break;
            case Opcode.POPFX:
                if (stack.Count != 0)
                    stack.Pop();
                --stackBalance;
                break;
            case Opcode.PROC:
                break;
            case Opcode.COMM:
                {
                    short index = instruction.Operand.Int16Value;
                    foreach (var parameter in mFunctions[index].Parameters)
                    {
                        if (stack.Count != 0)
                            stack.Pop();
                        --stackBalance;
                    }

                    lastFunction = mFunctions[index];
                }
                break;
            case Opcode.END:
                break;
            case Opcode.JUMP:
                break;
            case Opcode.CALL:
                break;
            case Opcode.RUN:
                break;
            case Opcode.GOTO:
                break;
            case Opcode.ADD:
            case Opcode.SUB:
            case Opcode.MUL:
            case Opcode.DIV:
                {
                    if (stack.Count != 0)
                        stack.Pop();
                    --stackBalance;
                }
                break;
            case Opcode.MINUS:
            case Opcode.NOT:
                break;
            case Opcode.OR:
            case Opcode.AND:
            case Opcode.EQ:
            case Opcode.NEQ:
            case Opcode.S:
            case Opcode.L:
            case Opcode.SE:
            case Opcode.LE:
                {
                    if (stack.Count != 0)
                        stack.Pop();
                    --stackBalance;
                }
                break;
            case Opcode.IF:
                {
                    if (stack.Count != 0)
                        stack.Pop();
                    --stackBalance;
                }
                break;
            case Opcode.PUSHIS:
                stack.Push(StackValueType.Int);
                ++stackBalance;
                break;
            case Opcode.PUSHLIX:
                stack.Push(StackValueType.Int);
                ++stackBalance;
                break;
            case Opcode.PUSHLFX:
                stack.Push(StackValueType.Float);
                ++stackBalance;
                break;
            case Opcode.POPLIX:
                if (stack.Count != 0)
                    stack.Pop();
                --stackBalance;
                break;
            case Opcode.POPLFX:
                if (stack.Count != 0)
                    stack.Pop();
                --stackBalance;
                break;
            case Opcode.PUSHSTR:
                stack.Push(StackValueType.String);
                ++stackBalance;
                break;
        }

        var snapshot = new StackSnapshot();
        snapshot.Stack = stack;
        snapshot.StackBalance = stackBalance;

        return snapshot;
    }

    //
    // Procedure evaluation
    //
    private void InitializeProcedureEvaluationState(Procedure procedure)
    {
        mProcedure = procedure;
        mInstructions = procedure.Instructions;
        mEvaluatedInstructionIndex = 0;
        mEvaluationStatementStack = new Stack<EvaluatedStatement>();
        mExpressionStack = new Stack<EvaluatedStatement>();
        mReturnKind = ValueKind.Void;
        mParameters = new List<Parameter>();
        mProcedureLocalVariables = new List<EvaluatedIdentifierReference>();

        // Add symbolic return address onto the stack
        PushStatement(
            new Identifier("<>__ReturnAddress"));
    }

    private bool TryEvaluateProcedure(Procedure procedure, out EvaluatedProcedure evaluatedProcedure)
    {
        LogInfo($"Evaluating procedure: '{procedure.Name}'");

        // Initialize
        InitializeProcedureEvaluationState(procedure);

        // Enter procedure scope
        PushScope();

        // Evaluate instructions
        if (!TryEvaluateInstructions())
        {
            LogError($"Failed to evaluate procedure '{procedure.Name}''s instructions");
            evaluatedProcedure = null;
            return false;
        }

        // Statements, yay!
        var evaluatedStatements = mEvaluationStatementStack.ToList();
        evaluatedStatements.Reverse();

        var first = evaluatedStatements.FirstOrDefault();
        if (first != null && first.Statement is Identifier identifier)
        {
            if (identifier.Text == "<>__ReturnAddress")
                evaluatedStatements.Remove(first);
        }

        // Build result
        evaluatedProcedure = new EvaluatedProcedure
        {
            Procedure = procedure,
            Scope = Scope,
            Statements = evaluatedStatements,
            ReturnKind = mReturnKind,
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
        foreach (var instruction in mProcedure.Instructions)
        {
            if (!TryEvaluateInstruction(instruction))
            {
                LogError($"Failed to evaluate instruction: {instruction}");
                return false;
            }

            ++mEvaluatedInstructionIndex;
        }

        return true;
    }

    private bool TryEvaluateInstruction(Instruction instruction)
    {
        //LogInfo( $"Evaluating instruction: {instruction}" );
        // Todo: implement expression stack

        switch (instruction.Opcode)
        {
            // Push integer to stack
            case Opcode.PUSHI:
                PushStatement(new IntLiteral(instruction.Operand.Int32Value));
                ++mRealStackCount;
                break;

            // Push float to stack
            case Opcode.PUSHF:
                PushStatement(new FloatLiteral(instruction.Operand.SingleValue));
                ++mRealStackCount;
                break;

            // Push value of global integer variable to stack
            case Opcode.PUSHIX:
                {
                    short index = instruction.Operand.Int16Value;
                    if (!Scope.TryGetGlobalIntVariable(index, out var declaration))
                    {
                        LogError($"Referenced undeclared global int variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Int, index, VariableIndexKind.Explicit, out declaration))
                        {
                            LogError("Failed to declare global int variable for PUSHIX");
                            return false;
                        }
                    }

                    PushStatement(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;

            // Push value of global float variable to stack
            case Opcode.PUSHIF:
                {
                    short index = instruction.Operand.Int16Value;
                    if (!Scope.TryGetGlobalFloatVariable(index, out var declaration))
                    {
                        LogError($"Referenced undeclared global float variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Float, index, VariableIndexKind.Explicit, out declaration))
                        {
                            LogError("Failed to declare global float variable for PUSHIF");
                            return false;
                        }
                    }

                    PushStatement(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;

            // Push return value of last function to stack
            case Opcode.PUSHREG:
                {
                    if (mLastFunctionCall == null)
                    {
                        // P3P does this
                        // Compiler bug?
                        LogError("PUSHREG before a function call!");
                        PushExpression(new IntLiteral(0));
                    }
                    else
                    {
                        if (mLastFunctionCall.ExpressionValueKind == ValueKind.Void)
                        {
                            LogError($"Result of void-returning function '{mLastFunctionCall.Identifier}' was used");
                        }

                        PushStatement(mLastFunctionCall);
                    }

                    ++mRealStackCount;
                }
                break;

            // Load top stack value into global integer variable
            case Opcode.POPIX:
                {
                    short index = instruction.Operand.Int16Value;

                    if (!Scope.TryGetGlobalIntVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Int, index, VariableIndexKind.Explicit, out declaration))
                        {
                            LogError("Failed to declare global int variable for POPIX");
                            return false;
                        }
                    }

                    if (!TryPopExpression(out var value))
                    {
                        LogError($"Failed to pop expression for global int variable assignment");
                        return false;
                    }

                    PushStatement(new AssignmentOperator(declaration.Identifier, value));
                    --mRealStackCount;
                }
                break;

            // Load top stack value into global float variable
            case Opcode.POPFX:
                {
                    short index = instruction.Operand.Int16Value;

                    if (!Scope.TryGetGlobalFloatVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Float, index, VariableIndexKind.Explicit, out declaration))
                        {
                            LogError("Failed to declare global float variable for POPIX");
                            return false;
                        }
                    }

                    if (!TryPopExpression(out var value))
                    {
                        LogError("Failed to pop expression for global float variable assignment");
                        return false;
                    }

                    PushStatement(new AssignmentOperator(declaration.Identifier, value));
                    --mRealStackCount;
                }
                break;

            // Marker for a procedure start
            // Doesn't really do anything 
            case Opcode.PROC:
                break;

            // Call to function
            case Opcode.COMM:
                {
                    short index = instruction.Operand.Int16Value;
                    if (!mFunctions.TryGetValue(index, out var function))
                    {
                        LogError("Unknown function: registration of functions must have failed");
                        return false;
                    }

                    var arguments = new List<Argument>();
                    foreach (var parameter in function.Parameters)
                    {
                        if (!TryPopExpression(out var argument))
                        {
                            LogError($"Failed to pop argument off stack for parameter: {parameter} of function: {function}");
                            if (StrictMode)
                                return false;

                            // Try to recover
                            argument = new Identifier("MISSING_ARGUMENT");
                        }

                        --mRealStackCount;
                        arguments.Add(new Argument(argument));
                    }

                    var callOperator = new CallOperator(
                        function.ReturnType.ValueKind,
                        function.Identifier,
                        arguments);

                    mLastFunctionCall = callOperator;

                    // Check if PUSHREG doesn't come next next
                    int nextCommIndex = mInstructions
                        .GetRange(mEvaluatedInstructionIndex + 1, mInstructions.Count - (mEvaluatedInstructionIndex + 1))
                        .FindIndex(x => x.Opcode == Opcode.COMM);

                    if (nextCommIndex == -1)
                        nextCommIndex = mInstructions.Count - 1;
                    else
                        nextCommIndex += mEvaluatedInstructionIndex + 1;

                    // Check if PUSHREG comes up between this and the next COMM instruction
                    // ReSharper disable once SimplifyLinqExpression
                    if (!mInstructions.GetRange(mEvaluatedInstructionIndex, nextCommIndex - mEvaluatedInstructionIndex).Any(x => x.Opcode == Opcode.PUSHREG))
                    {
                        // If PUSHREG doesn't come before another COMM then the return value is unused
                        PushStatement(callOperator);
                    }

                    // Otherwise let PUSHREG push the call operator
                }
                break;

            // End of procedure
            // Jumps to value on stack
            case Opcode.END:
                {
                    // Todo: return value
                    PushStatement(new ReturnStatement());
                }
                break;

            // Jump to procedure
            // without saving return address
            case Opcode.JUMP:
            // Call procedure
            case Opcode.CALL:
                {
                    if (instruction.Opcode == Opcode.JUMP)
                    {
                        LogInfo("JUMP not implemented! Emulating as CALL");
                    }

                    // Todo: arguments
                    short index = instruction.Operand.Int16Value;
                    if (index < 0 || index >= mScript.Procedures.Count)
                    {
                        LogError($"CALL referenced invalid procedure index: {index}");
                        return false;
                    }

                    var procedure = mScript.Procedures[index];
                    int parameterCount;
                    var arguments = new List<Argument>();
                    if (mProcedures.TryGetValue(index, out var declaration))
                    {
                        parameterCount = declaration.Parameters.Count;
                    }
                    else
                    {
                        // Number of parameters is unknown at this time

                        //parameterCount = mRealStackCount;
                        parameterCount = 0;
                        var parameters = new List<Parameter>();
                        for (int i = 0; i < parameterCount; i++)
                            parameters.Add(new Parameter(ParameterModifier.None, new TypeIdentifier(ValueKind.Int), new Identifier($"param{i + 1}"), null));

                        declaration = new ProcedureDeclaration(
                            new TypeIdentifier(ValueKind.Void),
                            new Identifier(ValueKind.Procedure, procedure.Name),
                            parameters,
                            null);

                        mProcedures[index] = declaration;
                    }

                    for (int i = 0; i < parameterCount; i++)
                    {
                        if (!TryPopExpression(out var expression))
                        {
                            LogError("Failed to pop expression for argument");
                            return false;
                        }

                        arguments.Add(new Argument(expression));
                        --mRealStackCount;
                    }

                    var callOperator = new CallOperator(
                        declaration.ReturnType.ValueKind,
                        declaration.Identifier,
                        arguments);

                    PushStatement(callOperator);
                    mLastProcedureCall = callOperator;
                }
                break;

            case Opcode.RUN:
                {
                    // Todo:
                    LogError("Todo: RUN");
                    return false;
                }

            case Opcode.GOTO:
                {
                    short index = instruction.Operand.Int16Value;
                    var label = mProcedure.Labels[index];
                    PushStatement(
                        new GotoStatement(
                            new Identifier(ValueKind.Label, mProcedure.Labels[index].Name)),
                        label);
                }
                break;
            case Opcode.ADD:
                if (!TryPushBinaryExpression<AdditionOperator>())
                {
                    LogError("Failed to evaluate ADD");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.SUB:
                if (!TryPushBinaryExpression<SubtractionOperator>())
                {
                    LogError("Failed to evaluate SUB");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.MUL:
                if (!TryPushBinaryExpression<MultiplicationOperator>())
                {
                    LogError("Failed to evaluate MUL");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.DIV:
                if (!TryPushBinaryExpression<DivisionOperator>())
                {
                    LogError("Failed to evaluate DIV");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.MINUS:
                if (!TryPushUnaryExpression<NegationOperator>())
                {
                    LogError("Failed to evaluate MINUS");
                    return false;
                }
                break;
            case Opcode.NOT:
                if (!TryPushUnaryExpression<LogicalNotOperator>())
                {
                    LogError("Failed to evaluate NOT");
                    return false;
                }
                break;
            case Opcode.OR:
                if (!TryPushBinaryBooleanExpression<LogicalOrOperator>())
                {
                    LogError("Failed to evaluate OR");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.AND:
                if (!TryPushBinaryBooleanExpression<LogicalAndOperator>())
                {
                    LogError("Failed to evaluate AND");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.EQ:
                if (!TryPushBinaryBooleanExpression<EqualityOperator>())
                {
                    LogError("Failed to evaluate EQ");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.NEQ:
                if (!TryPushBinaryBooleanExpression<NonEqualityOperator>())
                {
                    LogError("Failed to evaluate NEQ");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.S:
                if (!TryPushBinaryExpression<LessThanOperator>())
                {
                    LogError("Failed to evaluate S");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.L:
                if (!TryPushBinaryExpression<GreaterThanOperator>())
                {
                    LogError("Failed to evaluate L");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.SE:
                if (!TryPushBinaryExpression<LessThanOrEqualOperator>())
                {
                    LogError("Failed to evaluate SE");
                    return false;
                }
                --mRealStackCount;
                break;
            case Opcode.LE:
                if (!TryPushBinaryExpression<GreaterThanOrEqualOperator>())
                {
                    LogError("Failed to evaluate LE");
                    return false;
                }
                --mRealStackCount;
                break;

            // If statement
            case Opcode.IF:
                {
                    // Get label for when if condition is not met
                    short index = instruction.Operand.Int16Value;
                    var label = mProcedure.Labels[index];

                    // Pop condition
                    if (!TryPopExpression(out var condition))
                    {
                        LogError("Failed to pop if statement condition expression");
                        return false;
                    }

                    // The body and else body is structured later
                    PushStatement(new IfStatement(
                        condition,
                        null,
                        null), label);
                }
                --mRealStackCount;
                break;

            // Push short
            case Opcode.PUSHIS:
                PushStatement(new IntLiteral(instruction.Operand.Int16Value));
                ++mRealStackCount;
                break;

            // Push local int variable value
            case Opcode.PUSHLIX:
                {
                    short index = instruction.Operand.Int16Value;
                    if (!Scope.TryGetLocalIntVariable(index, out var declaration))
                    {
                        // Probably a variable declared in the root scope
                        LogInfo($"Referenced undeclared local int variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Int, index, VariableIndexKind.Implicit, out declaration))
                        {
                            LogError("Failed to declare local float variable for PUSHLIX");
                            return false;
                        }
                    }

                    PushStatement(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;
            case Opcode.PUSHLFX:
                {
                    short index = instruction.Operand.Int16Value;
                    if (!Scope.TryGetLocalFloatVariable(index, out var declaration))
                    {
                        LogInfo($"Referenced undeclared local float variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Float, index, VariableIndexKind.Implicit, out declaration))
                        {
                            LogError("Failed to declare local int variable for PUSHLFX");
                            return false;
                        }
                    }

                    PushStatement(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;
            case Opcode.POPLIX:
                {
                    short index = instruction.Operand.Int16Value;

                    if (!Scope.TryGetLocalIntVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Int, index, VariableIndexKind.Implicit, out declaration))
                        {
                            LogError("Failed to declare variable for POPLIX");
                            return false;
                        }
                    }

                    if (!TryPopExpression(out var value))
                    {
                        LogError("Failed to pop expression for variable assignment");
                        return false;
                    }

                    PushStatement(new AssignmentOperator(declaration.Identifier, value));
                    --mRealStackCount;
                }
                break;
            case Opcode.POPLFX:
                {
                    short index = instruction.Operand.Int16Value;

                    if (!Scope.TryGetLocalFloatVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Float, index, VariableIndexKind.Implicit, out declaration))
                        {
                            LogError("Failed to declare variable for POPLFX");
                            return false;
                        }
                    }

                    if (!TryPopExpression(out var value))
                    {
                        LogError("Failed to pop expression for variable assignment");
                        return false;
                    }

                    PushStatement(new AssignmentOperator(declaration.Identifier, value));
                    --mRealStackCount;
                }
                break;
            case Opcode.PUSHSTR:
                {
                    var stringValue = instruction.Operand.StringValue;
                    PushStatement(new StringLiteral(stringValue));
                    ++mRealStackCount;
                }
                break;
            default:
                LogError($"Unimplemented opcode: {instruction.Opcode}");
                return false;
        }

        return true;
    }

    //
    // Evaluation stack control
    //
    private void PushStatement(Statement statement, Label referencedLabel = null)
    {
        var visitor = new StatementVisitor(this);
        visitor.Visit(statement);

        mEvaluationStatementStack.Push(
            new EvaluatedStatement(statement, mEvaluatedInstructionIndex, referencedLabel));
    }

    private bool TryPopStatement(out Statement statement)
    {
        if (mEvaluationStatementStack.Count == 1 /* return address */ )
        {
            statement = null;
            return false;
        }

        statement = mEvaluationStatementStack.Pop().Statement;
        return true;
    }

    private void PushExpression(Statement statement)
    {
        var visitor = new StatementVisitor(this);
        visitor.Visit(statement);

        mExpressionStack.Push(
            new EvaluatedStatement(statement, mEvaluatedInstructionIndex, null));
    }

    private bool TryPopExpression(out Expression expression)
    {
        if (!TryPopStatement(out var statement))
        {
            expression = null;
            return false;
        }

        expression = statement as Expression;
        return expression != null;
    }

    private bool TryPushBinaryExpression<T>() where T : BinaryExpression, new()
    {
        var binaryExpression = new T();
        if (!TryPopExpression(out var left))
        {
            return false;
        }

        if (!TryPopExpression(out var right))
        {
            return false;
        }

        binaryExpression.Left = left;
        binaryExpression.Right = right;

        PushStatement(binaryExpression);
        return true;
    }

    private bool TryPushBinaryBooleanExpression<T>() where T : BinaryExpression, new()
    {
        var binaryExpression = new T();
        if (!TryPopExpression(out var left))
        {
            return false;
        }

        if (!TryPopExpression(out var right))
        {
            return false;
        }

        // Check if the left expression is already returns a boolean value, and if so
        // omit the x == 0 or x == 1 expression
        if (left.ExpressionValueKind == ValueKind.Bool && right is IntLiteral intLiteral)
        {
            if (typeof(T) == typeof(NonEqualityOperator))
            {
                // NEQ
                if (intLiteral.Value == 0) //  x != false -> x
                {
                    PushStatement(left);
                    return true;
                }
                else if (intLiteral.Value == 1) // x != true -> !x
                {
                    PushStatement(new LogicalNotOperator(left));
                    return true;
                }
            }
            else
            {
                // OR, AND, EQ
                if (intLiteral.Value == 0) //  x == false -> !x
                {
                    PushStatement(new LogicalNotOperator(left));
                    return true;
                }
                else if (intLiteral.Value == 1) // x == true -> x
                {
                    PushStatement(left);
                    return true;
                }
            }
        }

        binaryExpression.Left = left;
        binaryExpression.Right = right;

        PushStatement(binaryExpression);

        return true;
    }

    private bool TryPushUnaryExpression<T>() where T : UnaryExpression, new()
    {
        var uanryExpression = new T();
        if (!TryPopExpression(out var operand))
        {
            return false;
        }

        uanryExpression.Operand = operand;

        PushStatement(uanryExpression);
        return true;
    }

    //
    // Logging
    //
    private void LogInfo(string message)
    {
        mLogger.Info($"{message}");
    }

    private void LogError(string message)
    {
        mLogger.Error($"{message}");

        if (Debugger.IsAttached)
        {
            //Debugger.Break();
        }
    }

    private class StatementVisitor : SyntaxNodeVisitor
    {
        private readonly Evaluator mEvaluator;

        public StatementVisitor(Evaluator evaluator)
        {
            mEvaluator = evaluator;
        }

        public override void Visit(Identifier identifier)
        {
            if (mEvaluator.Scope.Variables.Values.Any(x => x.Identifier.Text == identifier.Text))
            {
                mEvaluator.mProcedureLocalVariables.Add(
                    new EvaluatedIdentifierReference(identifier,
                        mEvaluator.mEvaluatedInstructionIndex));
            }

            base.Visit(identifier);
        }
    }
}
