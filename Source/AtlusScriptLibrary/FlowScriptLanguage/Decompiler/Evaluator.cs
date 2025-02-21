using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using MoreLinq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler;

internal class ProcedurePreEvaluationInfo
{
    public Procedure Procedure { get; set; }

    public List<StackValueType> ParameterTypes { get; set; } = new();

    public List<StackSnapshot> Snapshots { get; set; } = new();
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
    Return,
    Any
}

public class Evaluator
{
    private readonly Logger mLogger;

    // FlowScript evaluation
    private FlowScript mScript;
    private Dictionary<uint, FunctionDeclaration> mFunctions;
    private Dictionary<int, ProcedureDeclaration> mProcedures;
    private List<ProcedurePreEvaluationInfo> mProcedurePreEvaluationInfos;
    private Stack<EvaluatedScope> mScopeStack;

    private EvaluatedScope Scope => mScopeStack.Peek();

    // Procedure evaluation
    private Procedure mProcedure;
    private List<Instruction> mInstructions;
    private int mEvaluatedInstructionIndex;
    private int mRealStackCount;
    private Stack<EvaluatedStatement> mEvaluationStatementStack;
    private Stack<EvaluatedStatement> mEvaluationExpressionStack;
    private CallOperator mLastFunctionCall;
    private CallOperator mLastProcedureCall;
    private ValueKind mReturnKind;
    private List<Parameter> mParameters;
    private ProcedurePreEvaluationInfo mPreEvaluationInfo;
    private Stack<Parameter> mParameterStack;
    private List<EvaluatedIdentifierReference> mProcedureLocalVariables;
    private Expression mLastPopRegValue;

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
        mProcedurePreEvaluationInfos = PreEvaluateProcedures(flowScript);
        foreach (var proc in mProcedurePreEvaluationInfos)
        {
            for (int i = 0; i < proc.Procedure.Instructions.Count; i++)
            {
                var instr = proc.Procedure.Instructions[i];
                // TODO: make this more flexible
                // If a procedure only calls another procedure through CALL or JUMP, inherit its stack arguments
                if ((i == 1 && (instr.Opcode == Opcode.CALL || instr.Opcode == Opcode.JUMP)) &&
                    (
                        (i + 1 == proc.Procedure.Instructions.Count) || 
                        ((i + 1 == proc.Procedure.Instructions.Count - 1) && proc.Procedure.Instructions[i+1].Opcode == Opcode.END)
                    ))
                {
                    var calledProcInfo = mProcedurePreEvaluationInfos[instr.Operand.UInt16Value];
                    proc.ParameterTypes.AddRange(calledProcInfo.ParameterTypes);
                }
            }
        }

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
        mFunctions = new Dictionary<uint, FunctionDeclaration>();
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

    private bool TryDeclareVariable(VariableModifierKind modifierKind, ValueKind valueKind, ushort index, out VariableDeclaration declaration)
    {
        var modifier = new VariableModifier(modifierKind, new UIntLiteral(index));
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

    private bool IsVariableDeclared(VariableModifierKind modifierKind, ValueKind valueKind, ushort index)
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

    private void RegisterTopLevelVariables()
    {
        LogInfo("Registering top level variables");

        var foundIntVariables = new Dictionary<int, (Procedure Procedure, VariableModifierKind Modifier, ValueKind Type)>();
        var foundFloatVariables = new Dictionary<int, (Procedure Procedure, VariableModifierKind Modifier, ValueKind Type)>();

        void DeclareVariableIfNotDeclared((Procedure Procedure, VariableModifierKind Modifier, ValueKind Type) context, ushort index)
        {
            // If the procedures are different, then this variable can't be local to the scope of the procedure
            if (!IsVariableDeclared(context.Modifier, context.Type, index))
            {
                var result = TryDeclareVariable(context.Modifier, context.Type, index, out _);
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

                            var index = instruction.Operand.UInt16Value;

                            if (modifier != VariableModifierKind.Global && type == ValueKind.Int && foundIntVariables.TryGetValue(index, out var context))
                            {
                                // Check if it was declared in a different procedure than the one we're currently processing
                                if (procedure != context.Procedure)
                                {
                                    // If the procedures are different, then this variable can't be local to the scope of the procedure
                                    DeclareVariableIfNotDeclared(context, index);
                                }
                            }
                            else if (modifier != VariableModifierKind.Global && type == ValueKind.Float && foundFloatVariables.TryGetValue(index, out context))
                            {
                                // Check if it was declared in a different procedure than the one we're currently processing
                                if (procedure != context.Procedure)
                                {
                                    // If the procedures are different, then this variable can't be local to the scope of the procedure
                                    DeclareVariableIfNotDeclared(context, index);
                                }
                            }
                            else
                            {
                                context = (procedure, modifier, type);

                                if (modifier == VariableModifierKind.Global)
                                {
                                    // If it's a global, declare it anyway
                                    DeclareVariableIfNotDeclared(context, index);
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
            var index = instruction.Operand.UInt16Value;
            if (mFunctions.ContainsKey(index))
                continue;

            // Declare function
            var function = Library?.FlowScriptModules
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
        var snapshots = new List<StackSnapshot>();

        var previousSnapshot = new StackSnapshot();
        previousSnapshot.StackBalance = 1;
        previousSnapshot.Stack = new Stack<StackValueType>();
        previousSnapshot.Stack.Push(StackValueType.Return);

        FunctionDeclaration lastFunction = null;
        StackValueType regValueType = StackValueType.None;
        var stackArguments = new List<StackValueType>();

        for (int i = 0; i < procedure.Instructions.Count; i++)
        {
            var instruction = procedure.Instructions[i];
            var snapshot = PreEvaluateInstruction(instruction, previousSnapshot, stackArguments,
                ref lastFunction, ref regValueType);
            snapshots.Add(snapshot);
            previousSnapshot = snapshot;
        }

        var evaluationInfo = new ProcedurePreEvaluationInfo();
        evaluationInfo.Procedure = procedure;
        evaluationInfo.Snapshots = snapshots;
        evaluationInfo.ParameterTypes = stackArguments;

        return evaluationInfo;
    }

    private StackSnapshot PreEvaluateInstruction(Instruction instruction, StackSnapshot previousSnapshot, 
        List<StackValueType> parameterTypes, ref FunctionDeclaration lastFunction, ref StackValueType regValueType)
    {
        var stack = new Stack<StackValueType>();
        foreach (var valueType in previousSnapshot.Stack.Reverse())
            stack.Push(valueType);

        int stackBalance = previousSnapshot.StackBalance;

        StackValueType PopStackValue(params StackValueType[] expectedTypes)
        {
            var type = stack.Pop();
            if (expectedTypes.Contains(StackValueType.Any) && !expectedTypes.Contains(type))
                LogWarning($"Popped {type} off stack when any of [{string.Join(", ", expectedTypes)}] were expected");
            return type;
        }

        bool CanPopStackValue()
        {
            return stack.Count != 0 && stack.Peek() != StackValueType.Return;
        }

        switch (instruction.Opcode)
        {
            case Opcode.PUSHI:
                stack.Push(StackValueType.Int);
                break;
            case Opcode.PUSHF:
                stack.Push(StackValueType.Float);
                break;
            case Opcode.PUSHIX:
                stack.Push(StackValueType.Int);
                break;
            case Opcode.PUSHIF:
                stack.Push(StackValueType.Float);
                break;
            case Opcode.PUSHREG:
                stack.Push(regValueType);
                break;
            case Opcode.POPIX:
                if (CanPopStackValue())
                {
                    PopStackValue(StackValueType.Int);
                }
                else
                {
                    parameterTypes.Add(StackValueType.Int);
                }
                break;
            case Opcode.POPFX:
                if (CanPopStackValue())
                {
                    PopStackValue(StackValueType.Float);
                }
                else
                {
                    parameterTypes.Add(StackValueType.Float);
                }
                break;
            case Opcode.PROC:
                break;
            case Opcode.COMM:
                {
                    ushort index = instruction.Operand.UInt16Value;
                    foreach (var parameter in mFunctions[index].Parameters)
                    {
                        if (CanPopStackValue())
                        {
                            switch (parameter.Type.ValueKind)
                            {
                                case ValueKind.Bool:
                                case ValueKind.Int:
                                    PopStackValue(StackValueType.Int);
                                    break;
                                case ValueKind.Float:
                                    PopStackValue(StackValueType.Float);
                                    break;
                                case ValueKind.String:
                                    PopStackValue(StackValueType.String);
                                    break;
                                default:
                                    throw new NotImplementedException();
                            }
                        }
                        else
                        {
                            switch (parameter.Type.ValueKind)
                            {
                                case ValueKind.Bool:
                                case ValueKind.Int:
                                    parameterTypes.Add(StackValueType.Int);
                                    break;
                                case ValueKind.Float:
                                    parameterTypes.Add(StackValueType.Float);
                                    break;
                                case ValueKind.String:
                                    parameterTypes.Add(StackValueType.String);
                                    break;
                                default:
                                    throw new NotImplementedException();
                            }
                        }
                    }

                    lastFunction = mFunctions[index];
                    switch (lastFunction.ReturnType.ValueKind)
                    {
                        case ValueKind.Bool:
                        case ValueKind.Int:
                            regValueType = StackValueType.Int;
                            break;
                        case ValueKind.Float:
                            regValueType = StackValueType.Float;
                            break;
                    }
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
                    if (CanPopStackValue())
                    {
                        var typeA = PopStackValue(StackValueType.Int, StackValueType.Float);
                        if (CanPopStackValue())
                        {
                            var typeB = PopStackValue(StackValueType.Int, StackValueType.Float);
                            if (typeA == StackValueType.Float || typeB == StackValueType.Float)
                            {
                                stack.Push(StackValueType.Float);
                            }
                            else
                            {
                                stack.Push(StackValueType.Int);
                            }    
                        }
                        else
                        {
                            LogError("Unable to pop value of stack");
                        }
                    }
                    else
                    {
                        LogError("Unable to pop value of stack");
                    }
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
                    if (CanPopStackValue())
                    {
                        var typeA = PopStackValue(StackValueType.Int, StackValueType.Float);
                        if (CanPopStackValue())
                        {
                            var typeB = PopStackValue(StackValueType.Int, StackValueType.Float);
                            if (typeA == StackValueType.Float || typeB == StackValueType.Float)
                            {
                                stack.Push(StackValueType.Float);
                            }
                            else
                            {
                                stack.Push(StackValueType.Int);
                            }
                        }
                        else
                        {
                            LogError("Unable to pop value of stack");
                        }
                    }
                    else
                    {
                        LogError("Unable to pop value of stack");
                    }
                }
                break;
            case Opcode.IF:
                {
                    if (CanPopStackValue())
                    {
                        PopStackValue(StackValueType.Int, StackValueType.Float);
                    }
                    else
                    {
                        LogError("Unable to pop value of stack");
                    }
                }
                break;
            case Opcode.PUSHIS:
                stack.Push(StackValueType.Int);
                break;
            case Opcode.PUSHLIX:
                stack.Push(StackValueType.Int);
                break;
            case Opcode.PUSHLFX:
                stack.Push(StackValueType.Float);
                break;
            case Opcode.POPLIX:
                if (CanPopStackValue())
                {
                    PopStackValue(StackValueType.Int);
                }
                else
                {
                    parameterTypes.Add(StackValueType.Int);
                }
                break;
            case Opcode.POPLFX:
                if (CanPopStackValue())
                {
                    PopStackValue(StackValueType.Float);
                }
                else
                {
                    parameterTypes.Add(StackValueType.Float);
                }
                break;
            case Opcode.PUSHSTR:
                stack.Push(StackValueType.String);
                break;
            case Opcode.POPREG:
                if (stack.Count != 0)
                {
                    regValueType = stack.Pop();
                }
                else
                {
                    parameterTypes.Add(StackValueType.Any);
                    regValueType = StackValueType.Any;
                }
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
        mEvaluationExpressionStack = new Stack<EvaluatedStatement>();
        mReturnKind = ValueKind.Void;
        mParameters = new List<Parameter>();
        mPreEvaluationInfo = mProcedurePreEvaluationInfos.Where(x => x.Procedure == procedure).FirstOrDefault();
        for (int i = 0; i < mPreEvaluationInfo.ParameterTypes.Count; i++)
        {
            var parameterType = mPreEvaluationInfo.ParameterTypes[i];
            var typeIdentifier = parameterType switch
            {
                StackValueType.Int => new TypeIdentifier("int"),
                StackValueType.Float => new TypeIdentifier("float"),
                StackValueType.String => new TypeIdentifier("string"),
                _ => new TypeIdentifier("int") // TODO fix
            };
            mParameters.Add(new Parameter()
            {
                Identifier = new Identifier($"param{i}"),
                Type = typeIdentifier,
            });
        }
        mProcedureLocalVariables = new List<EvaluatedIdentifierReference>();

        foreach (var param in mParameters.AsEnumerable().Reverse())
        {
            PushExpression(param.Identifier);
        }
    }

    private bool TryEvaluateProcedure(Procedure procedure, out EvaluatedProcedure evaluatedProcedure)
    {
        LogInfo($"Evaluating procedure: '{procedure.Name}'");

        // Initialize
        InitializeProcedureEvaluationState(procedure);

        // Enter procedure scope
        PushScope();

        // Add symbolic return address onto the stack
        PushExpression(
            new Identifier("__RETURN_ADDRESS"));

        // Evaluate instructions
        if (!TryEvaluateInstructions())
        {
            LogError($"Failed to evaluate procedure '{procedure.Name}''s instructions");
            evaluatedProcedure = null;
            return false;
        }

        // Statements, yay!
        var evaluatedStatements = mEvaluationStatementStack
            .Union(mEvaluationExpressionStack)
            .OrderBy(x => x.InstructionIndex)
            .ToList();

        var first = evaluatedStatements.FirstOrDefault();
        if (first != null && first.Statement is Identifier identifier)
        {
            if (identifier.Text == "__RETURN_ADDRESS")
                evaluatedStatements.Remove(first);
        }

        // Generates incorrect code in some cases
        // Needs to be done in pre-eval
        //if (Library is null)
        //{
        //    foreach (var item in evaluatedStatements.ToList())
        //    {
        //        if (mInstructions[item.InstructionIndex].Opcode == Opcode.COMM)
        //        {
        //            if (item.Statement is CallOperator callExpr)
        //            {
        //                var argumentExpressions = evaluatedStatements
        //                    .Where(x => mEvaluationExpressionStack.Contains(x))
        //                    .Where(x => x.InstructionIndex < item.InstructionIndex && x.Statement is Expression)
        //                    .ToList();
        //                argumentExpressions.Reverse();
        //                foreach (var expr in argumentExpressions)
        //                {
        //                    evaluatedStatements.Remove(expr);
        //                    callExpr.Arguments.Add(new Argument() { Expression = (Expression)expr.Statement });
        //                }
        //            }
        //        }
        //    }
        //}

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
            LogDebug($"Evaluating instruction {instruction} at index {mEvaluatedInstructionIndex}");
            if (!TryEvaluateInstruction(instruction))
            {
                LogError($"Failed to evaluate instruction: {instruction}");
                if (StrictMode)
                    return false;
                else
                    mEvaluationStatementStack.Push(new EvaluatedStatement(new StringLiteral($"Failed to evaluate instruction {instruction} at index {mEvaluatedInstructionIndex}"), mEvaluatedInstructionIndex, null));
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
                PushExpression(new UIntLiteral(instruction.Operand.UInt32Value));
                ++mRealStackCount;
                break;

            // Push float to stack
            case Opcode.PUSHF:
                PushExpression(new FloatLiteral(instruction.Operand.SingleValue));
                ++mRealStackCount;
                break;

            // Push value of global integer variable to stack
            case Opcode.PUSHIX:
                {
                    var index = instruction.Operand.UInt16Value;
                    if (!Scope.TryGetGlobalIntVariable(index, out var declaration))
                    {
                        LogError($"Referenced undeclared global int variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Int, index, out declaration))
                        {
                            LogError("Failed to declare global int variable for PUSHIX");
                            return false;
                        }
                    }

                    PushExpression(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;

            // Push value of global float variable to stack
            case Opcode.PUSHIF:
                {
                    var index = instruction.Operand.UInt16Value;
                    if (!Scope.TryGetGlobalFloatVariable(index, out var declaration))
                    {
                        LogError($"Referenced undeclared global float variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Float, index, out declaration))
                        {
                            LogError("Failed to declare global float variable for PUSHIF");
                            return false;
                        }
                    }

                    PushExpression(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;

            // Push return value of last function to stack
            case Opcode.PUSHREG:
                {
                    if (mLastFunctionCall != null)
                    {
                        if (mLastFunctionCall.ExpressionValueKind == ValueKind.Void)
                        {
                            LogError($"Result of void-returning function '{mLastFunctionCall.Identifier}' was used");
                        }

                        PushExpression(mLastFunctionCall);
                    }
                    else
                    {
                        PushExpression(new CallOperator(new Identifier("__PUSHREG")));
                    }

                    ++mRealStackCount;
                }
                break;

            // Load top stack value into global integer variable
            case Opcode.POPIX:
                {
                    var index = instruction.Operand.UInt16Value;

                    if (!Scope.TryGetGlobalIntVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Int, index, out declaration))
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
                    var index = instruction.Operand.UInt16Value;

                    if (!Scope.TryGetGlobalFloatVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Global, ValueKind.Float, index, out declaration))
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
                    ushort index = instruction.Operand.UInt16Value;
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
                    mLastPopRegValue = null;

                    // Check if PUSHREG doesn't come next next
                    int nextCommIndex = mInstructions
                        .GetRange(mEvaluatedInstructionIndex + 1, mInstructions.Count - (mEvaluatedInstructionIndex + 1))
                        .FindIndex(x => x.Opcode == Opcode.COMM);

                    if (nextCommIndex == -1)
                        nextCommIndex = mInstructions.Count - 1;
                    else
                        nextCommIndex += mEvaluatedInstructionIndex + 1;

                    // Check if PUSHREG comes up between this and the next COMM instruction
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
                    var index = instruction.Operand.UInt16Value;
                    if (index < 0 || index >= mScript.Procedures.Count)
                    {
                        LogError($"CALL referenced invalid procedure index: {index}");
                        return false;
                    }

                    var procedure = mScript.Procedures[index];
                    int parameterCount = 0;
                    var arguments = new List<Argument>();
                    var procedurePreEvalInfo = mProcedurePreEvaluationInfos.FirstOrDefault(p => p.Procedure == procedure);
                    parameterCount = procedurePreEvalInfo?.ParameterTypes.Count ?? 0;

                    if (instruction.Opcode == Opcode.JUMP)
                    {
                        // We're using the return address of the callee for this one, so pop that first so it does not get passed an as argument
                        TryPopExpression(out var _);
                    }

                    for (int i = 0; i < parameterCount; i++)
                    {
                        if (!TryPopExpression(out var expression))
                        {
                            LogError("Failed to pop expression for argument");

                            if (StrictMode)
                                return false;

                            // Try to recover
                            expression = new Identifier("MISSING_ARGUMENT");
                        }

                        arguments.Add(new Argument(expression));
                        --mRealStackCount;
                    }

                    CallOperator callOperator;
                    if (instruction.Opcode == Opcode.JUMP)
                    {
                        var jumpCallArguments = new List<Argument>()
                        {
                            new(new Identifier(ValueKind.Procedure, procedure.Name))
                        };
                        jumpCallArguments.AddRange(arguments);
                        callOperator = new CallOperator(
                            ValueKind.Void,
                            new Identifier("__JUMP"),
                            jumpCallArguments);
                    }
                    else
                    {
                        callOperator = new CallOperator(
                            ValueKind.Void,
                            new Identifier(ValueKind.Procedure, procedure.Name),
                            arguments);
                    }

                    PushStatement(callOperator);
                    mLastProcedureCall = callOperator;
                }
                break;

            case Opcode.RUN:
                {
                    // Todo:
                    LogError("Todo: RUN");
                    PushStatement(new CallOperator(new Identifier("__RUN")));
                }
                break;

            case Opcode.GOTO:
                {
                    var index = instruction.Operand.UInt16Value;
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
                    var index = instruction.Operand.UInt16Value;
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
                PushExpression(new UIntLiteral(instruction.Operand.UInt16Value));
                ++mRealStackCount;
                break;

            // Push local int variable value
            case Opcode.PUSHLIX:
                {
                    var index = instruction.Operand.UInt16Value;
                    if (!Scope.TryGetLocalIntVariable(index, out var declaration))
                    {
                        // Probably a variable declared in the root scope
                        LogInfo($"Referenced undeclared local int variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Int, index, out declaration))
                        {
                            LogError("Failed to declare local float variable for PUSHLIX");
                            return false;
                        }
                    }

                    PushExpression(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;
            case Opcode.PUSHLFX:
                {
                    var index = instruction.Operand.UInt16Value;
                    if (!Scope.TryGetLocalFloatVariable(index, out var declaration))
                    {
                        LogInfo($"Referenced undeclared local float variable: '{index}'");
                        //return false;

                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Float, index, out declaration))
                        {
                            LogError("Failed to declare local int variable for PUSHLFX");
                            return false;
                        }
                    }

                    PushExpression(declaration.Identifier);
                    ++mRealStackCount;
                }
                break;
            case Opcode.POPLIX:
                {
                    var index = instruction.Operand.UInt16Value;

                    if (!Scope.TryGetLocalIntVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Int, index, out declaration))
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
                    var index = instruction.Operand.UInt16Value;

                    if (!Scope.TryGetLocalFloatVariable(index, out var declaration))
                    {
                        // variable hasn't been declared yet
                        if (!TryDeclareVariable(VariableModifierKind.Local, ValueKind.Float, index, out declaration))
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
                    PushExpression(new StringLiteral(stringValue));
                    ++mRealStackCount;
                }
                break;
            case Opcode.POPREG:
                {
                    if (!TryPopExpression(out var value))
                    {
                        LogError($"Failed to pop expression for POPREG");
                        return false;
                    }

                    PushStatement(new CallOperator(new Identifier("__POPREG"), new Argument(value)));
                    mLastFunctionCall = null;
                    --mRealStackCount;
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
        if (mEvaluationStatementStack.Count == 0)
        {
            statement = null;
            return false;
        }

        statement = mEvaluationStatementStack.Pop().Statement;
        return true;
    }

    private void PushExpression(Expression expression)
    {
        var visitor = new StatementVisitor(this);
        visitor.Visit(expression);

        mEvaluationExpressionStack.Push(
            new EvaluatedStatement(expression, mEvaluatedInstructionIndex, null));
    }

    private bool TryPopExpression(out Expression expression)
    {
        if (mEvaluationExpressionStack.Count == 0)
        {
            expression = null;
            return false;
        }
        expression = mEvaluationExpressionStack.Pop().Statement as Expression;
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

        PushExpression(binaryExpression);
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
        if (left.ExpressionValueKind == ValueKind.Bool && right is IIntLiteral intLiteral)
        {
            if (typeof(T) == typeof(NonEqualityOperator))
            {
                // NEQ
                if (intLiteral.Value == 0) //  x != false -> x
                {
                    PushExpression(left);
                    return true;
                }
                else if (intLiteral.Value == 1) // x != true -> !x
                {
                    PushExpression(new LogicalNotOperator(left));
                    return true;
                }
            }
            else
            {
                // OR, AND, EQ
                if (intLiteral.Value == 0) //  x == false -> !x
                {
                    PushExpression(new LogicalNotOperator(left));
                    return true;
                }
                else if (intLiteral.Value == 1) // x == true -> x
                {
                    PushExpression(left);
                    return true;
                }
            }
        }

        binaryExpression.Left = left;
        binaryExpression.Right = right;

        PushExpression(binaryExpression);

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

        PushExpression(uanryExpression);
        return true;
    }

    //
    // Logging
    //
    private void LogInfo(string message)
    {
        mLogger.Info($"{message}");
    }

    private void LogWarning(string message)
    {
        mLogger.Warning($"{message}");

        if (Debugger.IsAttached)
        {
            //Debugger.Break();
        }
    }

    private void LogDebug(string message)
    {
        mLogger.Debug($"{message}");

        if (Debugger.IsAttached)
        {
            //Debugger.Break();
        }
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
