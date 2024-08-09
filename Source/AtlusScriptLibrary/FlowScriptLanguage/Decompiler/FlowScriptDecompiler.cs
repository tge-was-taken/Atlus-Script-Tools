using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.Common.Text;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using AtlusScriptLibrary.MessageScriptLanguage;
using AtlusScriptLibrary.MessageScriptLanguage.Decompiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler;

public class FlowScriptDecompiler
{
    private static readonly int[] sRoyalBits = { 0, 3072, 6144, 11264, 11776, 12288 };

    private readonly Logger mLogger;
    private EvaluationResult mEvaluatedScript;
    private CompilationUnit mCompilationUnit;
    private string mFilePath;

    // procedure state
    private EvaluatedProcedure mEvaluatedProcedure;

    // compositing state
    private List<EvaluatedStatement> mOriginalEvaluatedStatements;
    private List<EvaluatedStatement> mEvaluatedStatements;
    private Dictionary<Statement, int> mStatementInstructionIndexLookup;
    private Dictionary<int, List<EvaluatedStatement>> mIfStatementBodyMap;
    private Dictionary<int, List<EvaluatedStatement>> mIfStatementElseBodyMap;
    private bool mKeepLabelsAndGotos = false;
    private bool mConvertIfStatementsToGotos = false;

    /// <summary>
    /// Gets or sets the library registry.
    /// </summary>
    public Library Library { get; set; }

    /// <summary>
    /// Gets or sets whether the embedded MessageScript (if it exists) should be decompiled as well.
    /// True by default.
    /// </summary>
    public bool DecompileMessageScript { get; set; } = true;

    /// <summary>
    /// Gets or sets the file path for the decompiled MessageScript.
    /// </summary>
    public string MessageScriptFilePath { get; set; }

    /// <summary>
    /// Sum bit values together
    /// </summary>
    public bool SumBits { get; set; }

    /// <summary>
    /// Initializes a FlowScript decompiler.
    /// </summary>
    public FlowScriptDecompiler()
    {
        mLogger = new Logger(nameof(FlowScriptDecompiler));
    }

    /// <summary>
    /// Adds a decompiler log listener. Use this if you want to see what went wrong during decompilation.
    /// </summary>
    /// <param name="listener">The listener to add.</param>
    public void AddListener(LogListener listener)
    {
        listener.Subscribe(mLogger);
    }

    public bool TryDecompile(FlowScript flowScript, out CompilationUnit compilationUnit)
    {
        LogInfo("Start decompiling FlowScript");
        if (!TryDecompileScript(flowScript, out compilationUnit))
        {
            return false;
        }

        LogInfo("Done decompiling FlowScript");
        return true;
    }

    public bool TryDecompile(FlowScript flowScript, string filepath)
    {
        mFilePath = Path.GetFullPath(filepath);
        LogInfo($"FlowScript output path set to {mFilePath}");

        if (MessageScriptFilePath == null)
            MessageScriptFilePath = Path.ChangeExtension(mFilePath, "msg");

        LogInfo($"MessageScript output path set to {MessageScriptFilePath}");

        if (flowScript.MessageScript != null)
        {
            // Disambiguate message script dialog names so that the decompilation won't fail
            DisambiguateMessageScriptDialogNames(flowScript.MessageScript);

            if (DecompileMessageScript)
            {
                // Decompile embedded message script
                LogInfo("Writing decompiled MessageScript to file");
                using (var messageScriptDecompiler = new MessageScriptDecompiler(new FileTextWriter(MessageScriptFilePath)))
                {
                    messageScriptDecompiler.Library = Library;
                    messageScriptDecompiler.Decompile(flowScript.MessageScript);
                }
            }
        }

        // Decompile to decompilation unit
        if (!TryDecompile(flowScript, out var compilationUnit))
            return false;

        // Write out the decompilation unit
        LogInfo("Writing decompiled FlowScript to file");
        var writer = new CompilationUnitWriter();
        writer.Write(compilationUnit, filepath);

        return true;
    }

    // 
    // FlowScript Decompilation
    //
    private void InitializeScriptDecompilationState(EvaluationResult evaluationResult)
    {
        mEvaluatedScript = evaluationResult;
        mCompilationUnit = new CompilationUnit();
    }

    private bool TryDecompileScript(FlowScript flowScript, out CompilationUnit compilationUnit)
    {
        // Evaluate script
        if (!TryEvaluateScript(flowScript, out var evaluationResult))
        {
            LogError("Failed to evaluate script");
            compilationUnit = null;
            return false;
        }

        if (!TryDecompileScriptInternal(evaluationResult, out compilationUnit))
        {
            LogError("Failed to decompile script");
            compilationUnit = null;
            return false;
        }

        return true;
    }

    private bool TryEvaluateScript(FlowScript flowScript, out EvaluationResult evaluationResult)
    {
        var evaluator = new Evaluator();
        evaluator.Library = Library;
        evaluator.AddListener(new LoggerPassthroughListener(mLogger));
        if (!evaluator.TryEvaluateScript(flowScript, out evaluationResult))
        {
            LogError("Failed to evaluate script");
            evaluationResult = null;
            return false;
        }

        return true;
    }

    private bool TryDecompileScriptInternal(EvaluationResult evaluationResult, out CompilationUnit compilationUnit)
    {
        // Initialize decompiler
        InitializeScriptDecompilationState(evaluationResult);

        if (mEvaluatedScript.FlowScript.MessageScript != null && DecompileMessageScript)
        {
            if (MessageScriptFilePath == null)
            {
                LogError("Can't decompile MessageScript; MessageScript file path is not specified.");
                compilationUnit = null;
                return false;
            }

            var importPath = MessageScriptFilePath.Replace(Path.GetDirectoryName(mFilePath), "").TrimStart('\\');
            mCompilationUnit.Imports.Add(new Import(importPath));
        }

        // Build function declarations and add them to AST
        //BuildFunctionDeclarationSyntaxNodes();

        // Build script-local variable declarations and add them to AST
        BuildScriptLocalVariableDeclarationSyntaxNodes();

        // Build procedure declarations and add them to AST
        if (!TryBuildProcedureDeclarationSyntaxNodes())
        {
            LogError("Failed to decompile procedure declarations");
            compilationUnit = null;
            return false;
        }

        compilationUnit = mCompilationUnit;
        return true;
    }

    private void BuildFunctionDeclarationSyntaxNodes()
    {
        foreach (var functionDeclaration in mEvaluatedScript.Functions)
            mCompilationUnit.Declarations.Add(functionDeclaration);
    }

    private void BuildScriptLocalVariableDeclarationSyntaxNodes()
    {
        foreach (var flowScriptVariableDeclaration in mEvaluatedScript.Scope.Variables.Values)
            mCompilationUnit.Declarations.Add(flowScriptVariableDeclaration);
    }

    private bool TryBuildProcedureDeclarationSyntaxNodes()
    {
        // Decompile procedures
        foreach (var evaluatedProcedure in mEvaluatedScript.Procedures)
        {
            if (!TryDecompileProcedure(evaluatedProcedure, out var declaration))
            {
                LogError($"Failed to decompile procedure: {evaluatedProcedure.Procedure.Name}");
                return false;
            }

            mCompilationUnit.Declarations.Add(declaration);
        }

        return true;
    }

    //
    // Procedure decompilation
    //
    private void InitializeProcedureDecompilationState(EvaluatedProcedure procedure)
    {
        mEvaluatedProcedure = procedure;
    }

    private bool TryDecompileProcedure(EvaluatedProcedure evaluatedProcedure, out ProcedureDeclaration declaration)
    {
        LogInfo($"Decompiling procedure: {evaluatedProcedure.Procedure.Name}");
        InitializeProcedureDecompilationState(evaluatedProcedure);

        if (!TryCompositeEvaluatedInstructions(evaluatedProcedure.Statements, out var statements))
        {
            LogError("Failed to composite evaluated instructions");
            declaration = null;
            return false;
        }

        declaration = new ProcedureDeclaration(
            new IntLiteral(mEvaluatedScript.Procedures.IndexOf(evaluatedProcedure)),
            new TypeIdentifier(evaluatedProcedure.ReturnKind),
            new Identifier(ValueKind.Procedure, evaluatedProcedure.Procedure.Name),
            evaluatedProcedure.Parameters,
            new CompoundStatement(statements));

        return true;
    }

    //
    // Compositing
    //
    private void InitializeCompositionState(List<EvaluatedStatement> evaluatedStatements)
    {
        mOriginalEvaluatedStatements = evaluatedStatements;
        mEvaluatedStatements = mOriginalEvaluatedStatements.ToList();

        // Build lookup
        mStatementInstructionIndexLookup = new Dictionary<Statement, int>(evaluatedStatements.Count);
        foreach (var evaluatedStatement in evaluatedStatements)
            mStatementInstructionIndexLookup[evaluatedStatement.Statement] = evaluatedStatement.InstructionIndex;

        mIfStatementBodyMap = new Dictionary<int, List<EvaluatedStatement>>();
        mIfStatementElseBodyMap = new Dictionary<int, List<EvaluatedStatement>>();
        new Dictionary<int, int>();
    }

    private bool TryCompositeEvaluatedInstructions(List<EvaluatedStatement> evaluatedStatements, out List<Statement> statements)
    {
        InitializeCompositionState(evaluatedStatements);

        if (mEvaluatedScript.FlowScript.MessageScript != null && DecompileMessageScript)
            ReplaceUnnamedMessageScriptConstants();

        InsertFunctionCallEnumParameterValues();

        RemoveDefaultParameterValues();

        // Insert label declarations, they'll be used to build if statements
        InsertLabelDeclarations();

        // Build the if statement bodies, they rely on the label declarations
        BuildIfStatementMaps();

        // Coagulate variable assignments with declarations if possible
        // This also solves the issue of variable scoping in if statements
        CoagulateVariableDeclarationAssignments();

        // Remove redundant gotos
        if (!mKeepLabelsAndGotos)
            RemoveRedundantGotos();

        // Remove unreferenced labels
        if (!mKeepLabelsAndGotos)
            RemoveUnreferencedLabels();

        RemoveDuplicateReturnStatements();

        // Build if statements
        if (!mConvertIfStatementsToGotos)
            BuildIfStatements();

        AnnotateBitArgs();

        // Convert the evaluated statements to regular statements
        statements = mEvaluatedStatements
            .Select(x => x.Statement)
            .ToList();

        return true;
    }

    private void AnnotateBitArgs()
    {
        for (var j = 0; j < mEvaluatedStatements.Count; j++)
        {
            var evaluatedStatement = (EvaluatedStatement)mEvaluatedStatements[j];
            var calls = SyntaxNodeCollector<CallOperator>.Collect(evaluatedStatement.Statement);
            if (!calls.Any())
                continue;

            foreach (var call in calls)
            {
                var libFunc = Library.FlowScriptModules.SelectMany(x => x.Functions).FirstOrDefault(x => x.Name == call.Identifier.Text);
                if (libFunc == null)
                {
                    // procedure call or unknown function
                    continue;
                }

                for (int i = 0; i < libFunc.Parameters.Count; i++)
                {
                    if (libFunc.Parameters[i].Semantic != FlowScriptModuleParameterSemantic.BitId)
                    {
                        // only interested in bit parameters
                        continue;
                    }

                    var arg = call.Arguments[i];

                    // only handle add expressions
                    if (!(arg.Expression is AdditionOperator))
                        continue;

                    // exclude any expressions with identifiers in them
                    if (SyntaxNodeCollector<Identifier>.Collect(arg.Expression).Count > 0)
                        continue;

                    // sum literals
                    var literals = SyntaxNodeCollector<IntLiteral>.Collect(arg.Expression);
                    var sum = 0;
                    foreach (var literal in literals)
                        sum += literal.Value;

                    sum = sRoyalBits[sum >> 28] + sum & 0x0fffffff;

                    if (SumBits)
                    {
                        // Replace expression with sum of the expression
                        arg.Expression = new IntLiteral(sum);
                    }
                    else
                    {
                        // insert comment with bit value sum before usage of value
                        mEvaluatedStatements.Insert(j++, new EvaluatedStatement(new Comment($"bit id {arg.Expression} = {sum}", false), -1, null));
                    }
                }
            }
        }
    }

    private void RemoveDefaultParameterValues()
    {
        foreach (var evaluatedStatement in mEvaluatedStatements)
        {
            var calls = SyntaxNodeCollector<CallOperator>.Collect(evaluatedStatement.Statement);
            if (calls.Any())
            {
                foreach (var call in calls)
                {
                    var libFunc = Library.FlowScriptModules.SelectMany(x => x.Functions).FirstOrDefault(x => x.Name == call.Identifier.Text);
                    if (libFunc == null)
                    {
                        // procedure call or unknown function
                        continue;
                    }

                    var argIndex = 0;
                    for (int i = 0; i < libFunc.Parameters.Count; i++)
                    {
                        if (libFunc.Parameters[i].DefaultValue == null)
                        {
                            argIndex++;
                            continue;
                        }

                        var arg = call.Arguments[argIndex];
                        var defaultValue = Expression.FromText(libFunc.Parameters[i].DefaultValue);
                        if (arg.Expression is IntLiteral argLiteral &&
                             defaultValue is IntLiteral defaultValueLiteral &&
                             argLiteral.Equals(defaultValueLiteral))
                        {
                            call.Arguments.RemoveAt(argIndex);
                            argIndex--;
                        }

                        argIndex++;
                    }
                }
            }
        }
    }


    private void ReplaceUnnamedMessageScriptConstants()
    {
        foreach (var evaluatedStatement in mEvaluatedStatements)
        {
            var calls = SyntaxNodeCollector<CallOperator>.Collect(evaluatedStatement.Statement);
            if (calls.Any())
            {
                foreach (var call in calls)
                {
                    var libFunc = Library.FlowScriptModules.SelectMany(x => x.Functions).FirstOrDefault(x => x.Name == call.Identifier.Text);
                    if (libFunc == null)
                    {
                        // procedure call or unknown function
                        continue;
                    }

                    for (int i = 0; i < libFunc.Parameters.Count; i++)
                    {
                        if (libFunc.Parameters[i].Semantic != FlowScriptModuleParameterSemantic.MsgId &&
                            libFunc.Parameters[i].Semantic != FlowScriptModuleParameterSemantic.SelId)
                        {
                            // only interested in message parameters
                            continue;
                        }

                        var arg = call.Arguments[i];
                        if (!(arg.Expression is IntLiteral dialogIndex))
                        {
                            // only handle literals for now
                            // TODO: name constants in compound expressions used to initialize msg variables
                            continue;
                        }

                        if (dialogIndex >= mEvaluatedScript.FlowScript.MessageScript.Dialogs.Count)
                        {
                            // out of bounds index... weird
                            continue;
                        }

                        // rewrite expression to be a reference to the dialog name
                        arg.Expression = new Identifier(
                            ValueKind.Int,
                            mEvaluatedScript.FlowScript.MessageScript.Dialogs[dialogIndex.Value].Name);
                    }
                }
            }
        }
    }

    private void DisambiguateMessageScriptDialogNames(MessageScript script)
    {
        var usedNames = new Dictionary<string, int>();
        for (int i = 0; i < script.Dialogs.Count; i++)
        {
            var dialog = script.Dialogs[i];
            if (usedNames.TryGetValue(dialog.Name, out var occurences))
            {
                // Name already used, disambiguate it by appending a number (starting with 2).
                // DuplicateName2, DuplicateName3...
                usedNames[dialog.Name] = ++occurences;
                dialog.Name += occurences;
            }
            else
            {
                // Name previously unused. Initialize occurence counter to 1.
                usedNames[dialog.Name] = 1;
            }
        }
    }

    private void InsertFunctionCallEnumParameterValues()
    {
        foreach (var evaluatedStatement in mEvaluatedStatements)
        {
            var calls = SyntaxNodeCollector<CallOperator>.Collect(evaluatedStatement.Statement);
            foreach (var call in calls)
            {
                var libraryFunctions = Library.FlowScriptModules
                                              .SelectMany(x => x.Functions)
                                              .Where(x => x.Name == call.Identifier.Text)
                                              .ToList();

                if (libraryFunctions.Count == 0)
                    continue;

                if (libraryFunctions.Count != 1)
                {
                    LogError($"More than one library function defined with the name '{call.Identifier.Text}' exit; using first definition...");
                }

                var libraryFunction = libraryFunctions[0];

                for (var i = 0; i < libraryFunction.Parameters.Count; i++)
                {
                    var parameter = libraryFunction.Parameters[i];
                    Expression argument;

                    if (i < call.Arguments.Count)
                    {
                        argument = call.Arguments[i].Expression;
                    }
                    else
                    {
                        LogError($"Missing argument {i} for call expression: {call}");
                        continue;
                    }

                    if (!(argument is IntLiteral argumentValue))
                        continue;

                    var libraryEnum = Library.FlowScriptModules
                                                     .Where(x => x.Enums != null)
                                                     .SelectMany(x => x.Enums)
                                                     .FirstOrDefault(x => x.Name == parameter.Type);

                    if (libraryEnum == null)
                        continue;

                    var libraryEnumMember = libraryEnum.Members.FirstOrDefault(x => x.Value == argumentValue.Value);
                    if (libraryEnumMember == null)
                        continue;

                    call.Arguments[i].Expression = new MemberAccessExpression
                    {
                        Operand = new TypeIdentifier(libraryEnum.Name),
                        Member = new Identifier(libraryEnumMember.Name)
                    };
                }
            }
        }
    }

    private void InsertLabelDeclarations()
    {
        foreach (var label in mEvaluatedProcedure.Procedure.Labels)
        {
            // Find best index to insert the label at
            int insertionIndex = -1;
            int highestIndexBefore = -1;
            int lowestIndexAfter = int.MaxValue;
            for (int i = 0; i < mEvaluatedStatements.Count; i++)
            {
                var statement = mEvaluatedStatements[i];
                if (statement.InstructionIndex == label.InstructionIndex)
                {
                    insertionIndex = i;
                    break;
                }
                if (statement.InstructionIndex > label.InstructionIndex)
                {
                    if (statement.InstructionIndex < lowestIndexAfter)
                    {
                        lowestIndexAfter = statement.InstructionIndex;
                    }
                }
                else if (statement.InstructionIndex < label.InstructionIndex)
                {
                    if (statement.InstructionIndex > highestIndexBefore)
                    {
                        highestIndexBefore = statement.InstructionIndex;
                    }
                }
            }

            if (insertionIndex == -1)
            {
                int differenceBefore = label.InstructionIndex - highestIndexBefore;
                int differenceAfter = lowestIndexAfter - label.InstructionIndex;
                if (differenceBefore < differenceAfter)
                {
                    insertionIndex = mEvaluatedStatements.FindIndex(x => x.InstructionIndex == highestIndexBefore) + 1;
                }
                else
                {
                    insertionIndex = mEvaluatedStatements.FindIndex(x => x.InstructionIndex == lowestIndexAfter);
                }
            }

            // Insert label declaration
            mEvaluatedStatements.Insert(insertionIndex,
                new EvaluatedStatement(
                    new LabelDeclaration(
                        new Identifier(ValueKind.Label, label.Name)),
                    label.InstructionIndex,
                    label));
        }
    }

    private void BuildIfStatementMaps()
    {
        // Build if statement bodies
        var evaluatedIfStatements = mEvaluatedStatements.Where(x => x.Statement is IfStatement).ToList();
        foreach (var evaluatedIfStatement in evaluatedIfStatements)
        {
            var falseLabel = evaluatedIfStatement.ReferencedLabel;

            if (mConvertIfStatementsToGotos)
            {
                var index = mEvaluatedStatements.IndexOf(evaluatedIfStatement);
                var ifStatement = (IfStatement)evaluatedIfStatement.Statement;

                mEvaluatedStatements.Insert(index, new EvaluatedStatement(ifStatement.Condition,
                                                                                      evaluatedIfStatement.InstructionIndex - 1, null));
                mEvaluatedStatements[index + 1] = new EvaluatedStatement(
                    new GotoStatement(new Identifier(falseLabel.Name)), evaluatedIfStatement.InstructionIndex, falseLabel);
            }
            else
            {
                // Extract statements contained in the if statement's body
                var bodyEvaluatedStatements = mEvaluatedStatements
                    .Where(x => x != evaluatedIfStatement && x.InstructionIndex >= evaluatedIfStatement.InstructionIndex && x.InstructionIndex < falseLabel.InstructionIndex)
                    .ToList();

                // We keep the if statements in a map to retain evaluation info until we finally build the if statements
                mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex] = bodyEvaluatedStatements;

                // Detect else if
                var evaluatedGotoStatement = bodyEvaluatedStatements.LastOrDefault();
                if (evaluatedGotoStatement != null && evaluatedGotoStatement.Statement is GotoStatement)
                {
                    if (evaluatedGotoStatement.ReferencedLabel.InstructionIndex !=
                         evaluatedGotoStatement.InstructionIndex + 1)
                    {
                        // Try to detect if-else pattern
                        var elseBodyEvaluatedStatements = mEvaluatedStatements
                            .Where(x => x != evaluatedGotoStatement && x.InstructionIndex >= evaluatedGotoStatement.InstructionIndex && x.InstructionIndex < evaluatedGotoStatement.ReferencedLabel.InstructionIndex)
                            .ToList();

                        if (elseBodyEvaluatedStatements.Any())
                            mIfStatementElseBodyMap[evaluatedIfStatement.InstructionIndex] = elseBodyEvaluatedStatements;
                    }
                }
            }
        }

        if (mConvertIfStatementsToGotos)
            return;

        // Remove statements in if statement bodies from list of statements
        foreach (var evaluatedIfStatement in evaluatedIfStatements)
        {
            var body = mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex];
            mIfStatementElseBodyMap.TryGetValue(evaluatedIfStatement.InstructionIndex, out var elseBody);

            body.ForEach(x => mEvaluatedStatements.Remove(x));
            if (elseBody != null)
                elseBody.ForEach(x => mEvaluatedStatements.Remove(x));

            foreach (var ifStatementBodyMap in mIfStatementBodyMap)
            {
                if (ifStatementBodyMap.Value.Contains(evaluatedIfStatement))
                {
                    body.ForEach(x => ifStatementBodyMap.Value.Remove(x));
                    if (elseBody != null)
                        elseBody.ForEach(x => ifStatementBodyMap.Value.Remove(x));
                }
            }

            foreach (var ifStatementBodyMap in mIfStatementElseBodyMap)
            {
                if (ifStatementBodyMap.Value.Contains(evaluatedIfStatement))
                {
                    body.ForEach(x => ifStatementBodyMap.Value.Remove(x));
                    if (elseBody != null)
                        elseBody.ForEach(x => ifStatementBodyMap.Value.Remove(x));
                }
            }

        }

        // Clean up if statement bodies
        if (mKeepLabelsAndGotos)
            return;

        foreach (var evaluatedIfStatement in evaluatedIfStatements)
        {
            var bodyEvaluatedStatements = mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex];

            // Remove goto to after if statement inside body if it's right after the if statement body
            var evaluatedGotoStatement = bodyEvaluatedStatements.LastOrDefault();
            if (evaluatedGotoStatement != null && evaluatedGotoStatement.Statement is GotoStatement)
            {
                // Likely a single if statement
                if (evaluatedGotoStatement.ReferencedLabel.InstructionIndex == evaluatedGotoStatement.InstructionIndex + 1)
                {
                    bodyEvaluatedStatements.Remove(evaluatedGotoStatement);
                }

                if (mIfStatementElseBodyMap.TryGetValue(evaluatedIfStatement.InstructionIndex,
                    out var elseBodyEvaluatedStatements))
                {
                    if (elseBodyEvaluatedStatements.Any())
                    {
                        bodyEvaluatedStatements.Remove(evaluatedGotoStatement);

                        if (elseBodyEvaluatedStatements.First().Statement is LabelDeclaration)
                            elseBodyEvaluatedStatements.Remove(elseBodyEvaluatedStatements.First());

                        if (elseBodyEvaluatedStatements.Any() && elseBodyEvaluatedStatements.Last().Statement is GotoStatement)
                        {
                            var elseBodyGotoStatement = elseBodyEvaluatedStatements.Last();
                            if (elseBodyGotoStatement.ReferencedLabel.InstructionIndex ==
                                 elseBodyGotoStatement.InstructionIndex + 1)
                            {
                                elseBodyEvaluatedStatements.Remove(elseBodyGotoStatement);
                            }
                        }
                    }
                }
            }

        }
    }

    private void CoagulateVariableDeclarationAssignments()
    {
        foreach (var item in mEvaluatedProcedure.Scope.LocalIntVariables.Reverse())
            mEvaluatedStatements.Insert(0, new EvaluatedStatement(item.Value, -1, null));

        foreach (var item in mEvaluatedProcedure.Scope.LocalFloatVariables.Reverse())
            mEvaluatedStatements.Insert(0, new EvaluatedStatement(item.Value, -1, null));

        // Commented out due to being broken, sometimes causing expressions to disappear
        //CoagulateVariableDeclarationAssignmentsRecursively( mEvaluatedStatements, new HashSet<string>() );
    }

    private void CoagulateVariableDeclarationAssignmentsRecursively(List<EvaluatedStatement> evaluatedStatements, HashSet<string> parentScopeDeclaredVariables)
    {
        if (!evaluatedStatements.Any())
            return;

        int firstIndex = evaluatedStatements.First().InstructionIndex;
        int lastIndex = evaluatedStatements.Last().InstructionIndex;
        //LogInfo( $"Coagulating variable declarations and assignments: { firstIndex } - { lastIndex }" );

        // Declared variables in the current scope
        var declaredVariables = new HashSet<string>();

        var allIfStatements = mOriginalEvaluatedStatements
            .Where(x => x.InstructionIndex >= firstIndex)
            .Where(x => x.InstructionIndex <= lastIndex)
            .Where(x => x.Statement is IfStatement)
            .ToList();

        // All referenced variable identifiers in statements, and if statements
        var referencedLocalVariableIdentifiers =
            mEvaluatedProcedure.ReferencedVariables
                .Where(x => x.InstructionIndex >= firstIndex && x.InstructionIndex <= lastIndex)
                .GroupBy(x => x.Identifier.Text);

        foreach (var referencedLocalVariableIdentifier in referencedLocalVariableIdentifiers)
        {
            var identifierText = referencedLocalVariableIdentifier.Key;
            int firstReferenceInstructionIndex = referencedLocalVariableIdentifier.Min(x => x.InstructionIndex);

            // Check if the variable was declared in either the scope of the parent or the current scope
            if (parentScopeDeclaredVariables.Contains(identifierText)
                || declaredVariables.Contains(identifierText)
                || !mEvaluatedProcedure.Scope.Variables.TryGetValue(identifierText, out var declaration))
                continue;

            // Variable hasn't already been declared
            // Find the index of the statement
            int evaluatedStatementIndex = evaluatedStatements.FindIndex(x => x.InstructionIndex == firstReferenceInstructionIndex);
            Expression initializer = null;
            bool shouldDeclareBeforeIfStatements = false;
            bool accessedLaterInBody = referencedLocalVariableIdentifier.Any(x => evaluatedStatements.Any(y => y.InstructionIndex == x.InstructionIndex));

            // Hack: Edge case - variable was assigned a non existent value
            // This causes the assignment to not exist in the AST
            // So just insert the assignment before the first reference
            if (evaluatedStatementIndex == -1 &&
                evaluatedStatements.Any(x => x.InstructionIndex == firstReferenceInstructionIndex - 1) && evaluatedStatements.Any(x => x.InstructionIndex == firstReferenceInstructionIndex + 1))
            {
                evaluatedStatementIndex = evaluatedStatements.FindIndex(x => x.InstructionIndex == firstReferenceInstructionIndex - 1);
            }

            if (evaluatedStatementIndex == -1 && !mConvertIfStatementsToGotos)
            {
                // Referenced first in one of the if statements

                // But maybe it's accessed later in the body?              
                bool accessedInIfStatementOnce = false;
                var curIfStatements = allIfStatements;

                foreach (var ifStatement in allIfStatements)
                {
                    // Check condition
                    var conditionIdentifiers = SyntaxNodeCollector<Identifier>.Collect(((IfStatement)ifStatement.Statement).Condition);
                    if (conditionIdentifiers.Any(x => x.Text == referencedLocalVariableIdentifier.Key))
                    {
                        // Really Good Code
                        shouldDeclareBeforeIfStatements = true;
                        break;
                    }

                    // Check if any of instructions in the if body map to any of the instruction indices of the references
                    var body = mIfStatementBodyMap[ifStatement.InstructionIndex];
                    var bodyIdentifiers = body.SelectMany(x => SyntaxNodeCollector<Identifier>.Collect(x.Statement));
                    if (bodyIdentifiers.Any(x => x.Text == referencedLocalVariableIdentifier.Key))
                    {
                        if (!accessedInIfStatementOnce)
                        {
                            accessedInIfStatementOnce = true;
                            if (accessedLaterInBody)
                                shouldDeclareBeforeIfStatements = true;
                        }
                        else
                        {
                            shouldDeclareBeforeIfStatements = true;
                            break;
                        }
                    }

                    // Same for else body
                    if (mIfStatementElseBodyMap.TryGetValue(ifStatement.InstructionIndex, out var elseBody))
                    {
                        // Check if any of instructions in the if else body map to any of the instruction indices of the references
                        var elseBodyIdentifiers = body.SelectMany(x => SyntaxNodeCollector<Identifier>.Collect(x.Statement));
                        if (elseBodyIdentifiers.Any(x => x.Text == referencedLocalVariableIdentifier.Key))
                        {
                            if (!accessedInIfStatementOnce)
                            {
                                accessedInIfStatementOnce = true;
                                if (accessedLaterInBody)
                                    shouldDeclareBeforeIfStatements = true;
                            }
                            else
                            {
                                shouldDeclareBeforeIfStatements = true;
                                break;
                            }
                        }
                    }
                }
            }
            else
            {
                var evaluatedStatement = evaluatedStatements[evaluatedStatementIndex];

                // Check if the statement is an assignment expression
                // Which would mean we have an initializer
                if (evaluatedStatement.Statement is AssignmentOperator assignment)
                {
                    // Only match initializers if the target of the operator
                    // Is actually the same identifier
                    if (((Identifier)assignment.Left).Text == identifierText)
                    {
                        initializer = assignment.Right;
                    }
                }
            }

            if ((evaluatedStatementIndex != -1 || shouldDeclareBeforeIfStatements) && !mConvertIfStatementsToGotos)
            {
                // Find the best insertion index
                int insertionIndex;
                if (evaluatedStatementIndex != -1)
                    insertionIndex = evaluatedStatementIndex;
                else
                    insertionIndex = evaluatedStatements.IndexOf(allIfStatements.First());

                int instructionIndex = firstReferenceInstructionIndex;

                // Check if the variable has been referenced before in an if statement
                foreach (var evaluatedIfStatement in allIfStatements.Where(x => x.InstructionIndex <= firstReferenceInstructionIndex))
                {
                    var ifStatementBody = mIfStatementBodyMap[evaluatedIfStatement.InstructionIndex];
                    var referencedLocalVariableIdentifiersInIfStatementBody =
                        mEvaluatedProcedure.ReferencedVariables.Where(
                            x => ifStatementBody.Any(y => x.InstructionIndex == y.InstructionIndex));

                    if (referencedLocalVariableIdentifiersInIfStatementBody.Any(
                        x => x.Identifier.Text == identifierText))
                    {
                        // The variable was referenced in a previous if statement, so we should insert it before the start of the if statement
                        insertionIndex = evaluatedStatements.IndexOf(evaluatedIfStatement);
                        instructionIndex = evaluatedIfStatement.InstructionIndex - 1;

                        // Edge case
                        if (instructionIndex < 0)
                            instructionIndex = 0;

                        break;
                    }

                    if (mIfStatementElseBodyMap.TryGetValue(evaluatedIfStatement.InstructionIndex,
                        out var ifStatementElseBody))
                    {
                        var referencedLocalVariableIdentifiersInIfStatementElseBody =
                            mEvaluatedProcedure.ReferencedVariables.Where(
                                x => ifStatementElseBody.Any(y => x.InstructionIndex == y.InstructionIndex));

                        if (referencedLocalVariableIdentifiersInIfStatementElseBody.Any(
                            x => x.Identifier.Text == identifierText))
                        {
                            // The variable was referenced in a previous if statement, so we should insert it before the start of the if statement
                            insertionIndex = evaluatedStatements.IndexOf(evaluatedIfStatement);
                            instructionIndex = evaluatedIfStatement.InstructionIndex - 1;

                            // Edge case
                            if (instructionIndex < 0)
                                instructionIndex = 0;

                            break;
                        }
                    }
                }

                if (insertionIndex == -1)
                {
                    // Variable was referenced in both the body and in a nested if statement                      
                    if (evaluatedStatements.Any(x => x.Statement is IfStatement))
                    {
                        insertionIndex = evaluatedStatements.IndexOf(evaluatedStatements.First(x => x.Statement is IfStatement));
                    }
                    else
                    {
                        insertionIndex = 0;
                    }
                }

                if (insertionIndex != evaluatedStatementIndex)
                {
                    // If the insertion index isn't equal to the evaluated statement index
                    // Then that means it was previously referenced in the body of an if statement
                    // So we insert declaration before if statement in which it was used

                    // Just to be safe
                    declaration.Initializer = new IntLiteral(0);

                    evaluatedStatements.Insert(insertionIndex,
                        new EvaluatedStatement(declaration, instructionIndex, null));
                }
                else
                {
                    // If the insertion index is still the same, then that means we probably have a declaration with an assignment
                    // Or maybe we have a reference to an undeclared variable!

                    if (initializer == null)
                    {
                        // Reference to undeclared variable
                        LogInfo($"Reference to uninitialized variable! Adding 0 initializer: {declaration}");
                        initializer = new IntLiteral(0);
                    }

                    // Coagulate assignment with declaration
                    declaration.Initializer = initializer;
                    evaluatedStatements[evaluatedStatementIndex] = new EvaluatedStatement(
                        declaration, instructionIndex, null);
                }

                declaredVariables.Add(identifierText);
            }
        }

        // Merge parent scope with local scope
        foreach (string declaredVariable in parentScopeDeclaredVariables)
            declaredVariables.Add(declaredVariable);

        if (!mConvertIfStatementsToGotos)
        {
            var ifStatementsInScope = evaluatedStatements
                .Where(x => x.Statement is IfStatement);

            foreach (var ifStatement in ifStatementsInScope)
            {
                // Do the same for each if statement
                var body = mIfStatementBodyMap[ifStatement.InstructionIndex];
                CoagulateVariableDeclarationAssignmentsRecursively(body, declaredVariables);

                if (mIfStatementElseBodyMap.TryGetValue(ifStatement.InstructionIndex, out var elseBody))
                    CoagulateVariableDeclarationAssignmentsRecursively(elseBody, declaredVariables);
            }
        }
    }

    private void RemoveRedundantGotos()
    {
        foreach (var evaluatedStatement in mEvaluatedStatements.Where(x => x.Statement is GotoStatement).ToList())
        {
            if (evaluatedStatement.ReferencedLabel.InstructionIndex == evaluatedStatement.InstructionIndex + 1)
                mEvaluatedStatements.Remove(evaluatedStatement);
        }

        foreach (var body in mIfStatementBodyMap.Values)
        {
            foreach (var evaluatedStatement in body.Where(x => x.Statement is GotoStatement).ToList())
            {
                if (evaluatedStatement.ReferencedLabel.InstructionIndex == evaluatedStatement.InstructionIndex + 1)
                    mEvaluatedStatements.Remove(evaluatedStatement);
            }
        }

        foreach (var body in mIfStatementElseBodyMap.Values)
        {
            foreach (var evaluatedStatement in body.Where(x => x.Statement is GotoStatement).ToList())
            {
                if (evaluatedStatement.ReferencedLabel.InstructionIndex == evaluatedStatement.InstructionIndex + 1)
                    mEvaluatedStatements.Remove(evaluatedStatement);
            }
        }
    }

    private void RemoveUnreferencedLabels()
    {
        foreach (var evaluatedStatement in mEvaluatedStatements.Where(x => x.Statement is LabelDeclaration).ToList())
        {
            if (!IsLabelReferenced(evaluatedStatement.ReferencedLabel))
                mEvaluatedStatements.Remove(evaluatedStatement);
        }

        foreach (var body in mIfStatementBodyMap.Values)
        {
            foreach (var evaluatedStatement in body.Where(x => x.Statement is LabelDeclaration).ToList())
            {
                if (!IsLabelReferenced(evaluatedStatement.ReferencedLabel))
                    body.Remove(evaluatedStatement);
            }
        }

        foreach (var body in mIfStatementElseBodyMap.Values)
        {
            foreach (var evaluatedStatement in body.Where(x => x.Statement is LabelDeclaration).ToList())
            {
                if (!IsLabelReferenced(evaluatedStatement.ReferencedLabel))
                    body.Remove(evaluatedStatement);
            }
        }
    }

    private bool IsLabelReferenced(Label label)
    {
        foreach (var evaluatedStatement in mEvaluatedStatements)
        {
            if (evaluatedStatement.ReferencedLabel == label && evaluatedStatement.Statement is GotoStatement)
                return true;
        }

        foreach (var evaluatedStatement in mIfStatementBodyMap.Values.SelectMany(x => x))
        {
            if (evaluatedStatement.ReferencedLabel == label && evaluatedStatement.Statement is GotoStatement)
                return true;
        }

        foreach (var evaluatedStatement in mIfStatementElseBodyMap.Values.SelectMany(x => x))
        {
            if (evaluatedStatement.ReferencedLabel == label && evaluatedStatement.Statement is GotoStatement)
                return true;
        }

        return false;
    }

    private void RemoveDuplicateReturnStatements()
    {
        void RemoveDuplicateReturnStatements(List<EvaluatedStatement> statements)
        {
            var returnStatements = statements.Where(x => x.Statement is ReturnStatement).ToList();
            for (int i = 0; i < returnStatements.Count; i++)
            {
                if (i + 1 >= returnStatements.Count)
                    break;

                if ((returnStatements[i + 1].InstructionIndex - returnStatements[i].InstructionIndex) == 1)
                    statements.Remove(returnStatements[i]);
            }
        }

        RemoveDuplicateReturnStatements(mEvaluatedStatements);

        foreach (var body in mIfStatementBodyMap.Values)
            RemoveDuplicateReturnStatements(body);

        foreach (var body in mIfStatementElseBodyMap.Values)
            RemoveDuplicateReturnStatements(body);
    }

    private void BuildIfStatements()
    {
        foreach (var evaluatedStatement in mOriginalEvaluatedStatements.Where(x => x.Statement is IfStatement))
        {
            var ifStatement = (IfStatement)evaluatedStatement.Statement;

            var body = mIfStatementBodyMap[evaluatedStatement.InstructionIndex];
            ifStatement.Body = new CompoundStatement(body.Select(x => x.Statement).ToList());

            if (mIfStatementElseBodyMap.TryGetValue(evaluatedStatement.InstructionIndex, out var elseBody))
                ifStatement.ElseBody = new CompoundStatement(elseBody.Select(x => x.Statement).ToList());
        }
    }

    //
    // Logging
    //
    private void LogTrace(string message)
    {
        mLogger.Trace(message);
    }

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
}
