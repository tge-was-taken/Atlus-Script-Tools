using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler.Processing;
using AtlusScriptLibrary.FlowScriptLanguage.Decompiler;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using AtlusScriptLibrary.MessageScriptLanguage;
using AtlusScriptLibrary.MessageScriptLanguage.Compiler;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler;

/// <summary>
/// Represents the compiler for FlowScripts. Responsible for transforming FlowScript sources into code.
/// </summary>
public class FlowScriptCompiler
{
    //
    // compiler state
    //
    private readonly Logger mLogger;
    private readonly FormatVersion mFormatVersion;
    private readonly HashSet<int> mImportedFileHashSet;
    private bool mReresolveImports;
    private string mFilePath;
    private string mCurrentBaseDirectory;
    private FlowScript mScript;
    private int mNextLabelIndex;
    private Stack<ScopeContext> mScopeStack;
    private ScopeContext mRootScope;
    private VariableInfo mIntReturnValueVariable;
    private VariableInfo mFloatReturnValueVariable;
    private Dictionary<string, List<Instruction>> mProcedureInstructionCache;
    private (Import, FlowScript) mBaseBfImport;

    // variable indices
    private short mNextIntVariableIndex;
    private short mNextFloatVariableIndex;
    private short mNextGlobalIntVariableIndex = 255;   // We count the indices for the static variables *down* to
    private short mNextGlobalFloatVariableIndex = 255; // reduce the chance of conflict with the game's original scripts
    private short mNextIntArgumentVariableIndex;
    private short mNextFloatArgumentVariableIndex;
    private short mNextAiLocalVariableIndex;
    private short mNextAiGlobalVariableIndex;
    private short mNextCounterVariableIndex;

    //
    // procedure state
    //
    private ProcedureDeclaration mProcedureDeclaration;
    private List<Instruction> mInstructions;
    private Dictionary<string, LabelInfo> mLabels;

    private int mStackValueCount; // for debugging
    private IntrinsicSupport mInstrinsic;

    private ScopeContext Scope => mScopeStack.Peek();

    /// <summary>
    /// Gets or sets the encoding to use for any imported MessageScripts.
    /// </summary>
    public Encoding Encoding { get; set; }

    /// <summary>
    /// Gets or sets the library registry to use for any imported MessageScripts.
    /// </summary>
    public Library Library { get; set; }

    /// <summary>
    /// Gets or sets whether the compiler should output procedure tracing code.
    /// </summary>
    public bool EnableProcedureTracing { get; set; } = true;

    /// <summary>
    /// Gets or sets whether the compiler should output procedure call tracing code.
    /// </summary>
    public bool EnableProcedureCallTracing { get; set; }

    /// <summary>
    /// Gets or sets whether the compiler should output function call tracing code.
    /// </summary>
    public bool EnableFunctionCallTracing { get; set; }

    /// <summary>
    /// Gets or sets whether the compiler should use stack cookies
    /// </summary>
    public bool EnableStackCookie { get; set; }

    /// <summary>
    /// Gets or sets whether the compiler should generate hooks for all procedures imported from existing scripts.
    /// </summary>
    public ProcedureHookMode ProcedureHookMode { get; set; }

    /// <summary>
    /// If true when there are message name conflicts an existing message of the same name will be overwritten. 
    /// Otherwise an error will occur and the existing message will not be changed
    /// </summary>
    public bool OverwriteExistingMsgs { get; set; } = false;

    public bool Matching { get; set; } = true;

    /// <summary>
    /// Initializes a FlowScript compiler with the given format version.
    /// </summary>
    /// <param name="version"></param>
    public FlowScriptCompiler(FormatVersion version)
    {
        mLogger = new Logger(nameof(FlowScriptCompiler));
        mFormatVersion = version;
        mImportedFileHashSet = new HashSet<int>();
    }

    /// <summary>
    /// Adds a compiler log listener. Use this if you want to see what went wrong during compilation.
    /// </summary>
    /// <param name="listener">The listener to add.</param>
    public void AddListener(LogListener listener)
    {
        listener.Subscribe(mLogger);
    }

    /// <summary>
    /// Tries to compile the provided FlowScript source with given imports. Returns a boolean indicating if the operation succeeded.
    /// </summary>
    /// <param name="baseBfStream">A FileStream of the base bf file</param>
    /// <param name="imports">A List of paths to .bf, .flow, and .msg files that will be forcibly imported</param>
    /// <param name="flowScript">The compiled FlowScript</param>
    /// <returns>True if the file successfully compiled, false otherwise</returns>
    public bool TryCompileWithImports(FileStream baseBfStream, List<string> imports, string baseFlow, out FlowScript flowScript)
    {
        // Parse base flow file
        CompilationUnit compilationUnit;
        if (baseFlow == null)
            compilationUnit = new CompilationUnit();
        else
        {
            var file = File.Open(baseFlow, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                mFilePath = Path.GetFullPath(file.Name);
                mCurrentBaseDirectory = Path.GetDirectoryName(mFilePath);

                // Add hash for current file
                var hashAlgo = new MD5CryptoServiceProvider();
                var hashBytes = hashAlgo.ComputeHash(file);
                int hashInt = BitConverter.ToInt32(hashBytes, 0);
                mImportedFileHashSet.Add(hashInt);
                file.Position = 0;

                // Parse compilation unit
                var parser = new CompilationUnitParser();
                parser.AddListener(new LoggerPassthroughListener(mLogger));
                if (!parser.TryParse(file, out compilationUnit))
                {
                    Error("Failed to parse compilation unit");
                    flowScript = null;
                    return false;
                }
            }
            finally
            {
                file.Close();
            }
        }

        // Parse base bf
        if (baseBfStream != null)
        {
            var baseBf = FlowScript.FromStream(baseBfStream, Encoding, mFormatVersion, false);
            mBaseBfImport = (new Import(baseBfStream.Name), baseBf);
        }

        compilationUnit.Imports.AddRange(imports.Select(import => new Import(import)));
        mCurrentBaseDirectory = "";
        return TryCompile(compilationUnit, out flowScript);
    }

    /// <summary>
    /// Tries to compile the provided FlowScript source. Returns a boolean indicating if the operation succeeded.
    /// </summary>
    /// <param name="source"></param>
    /// <param name="flowScript"></param>
    /// <returns></returns>
    public bool TryCompile(string source, out FlowScript flowScript)
    {
        Info("Start compiling FlowScript from source");

        // Add source to prevent recursion
        mImportedFileHashSet.Add(source.GetHashCode());

        // Parse compilation unit
        var parser = new CompilationUnitParser();
        parser.AddListener(new LoggerPassthroughListener(mLogger));
        if (!parser.TryParse(source, out var compilationUnit))
        {
            Error("Failed to parse compilation unit");
            flowScript = null;
            return false;
        }

        mCurrentBaseDirectory = "";
        return TryCompile(compilationUnit, out flowScript);
    }

    /// <summary>
    /// Tries to compile the provided FlowScript source. Returns a boolean indicating if the operation succeeded.
    /// </summary>
    /// <param name="source"></param>
    /// <param name="flowScript"></param>
    /// <returns></returns>
    public bool TryCompile(Stream stream, out FlowScript flowScript)
    {
        if (stream is FileStream fileStream)
        {
            mFilePath = Path.GetFullPath(fileStream.Name);
            mCurrentBaseDirectory = Path.GetDirectoryName(mFilePath);
            Info($"Start compiling FlowScript from file '{mFilePath}'");
            Info($"Base directory set to '{mCurrentBaseDirectory}'");
        }
        else
        {
            Info("Start compiling FlowScript from baseBf");
            Warning("Because the input is not a file, this means imports will not work!");
        }

        // Add hash for current file
        var hashAlgo = new MD5CryptoServiceProvider();
        var hashBytes = hashAlgo.ComputeHash(stream);
        int hashInt = BitConverter.ToInt32(hashBytes, 0);
        mImportedFileHashSet.Add(hashInt);
        stream.Position = 0;

        // Parse compilation unit
        var parser = new CompilationUnitParser();
        parser.AddListener(new LoggerPassthroughListener(mLogger));
        if (!parser.TryParse(stream, out var compilationUnit))
        {
            Error("Failed to parse compilation unit");
            flowScript = null;
            return false;
        }

        return TryCompile(compilationUnit, out flowScript);
    }

    /// <summary>
    /// Tries to compile the provided FlowScript source. Returns a boolean indicating if the operation succeeded.
    /// </summary>
    /// <param name="source"></param>
    /// <param name="flowScript"></param>
    /// <returns></returns>
    public bool TryCompile(CompilationUnit compilationUnit, out FlowScript flowScript)
    {
        // Resolve types that are unresolved at parse time
        var resolver = new TypeResolver();
        resolver.AddListener(new LoggerPassthroughListener(mLogger));
        if (!resolver.TryResolveTypes(compilationUnit))
        {
            Error("Failed to resolve types in compilation unit");
            flowScript = null;
            return false;
        }

        // Syntax checker?

        // Compile compilation unit
        if (!TryCompileCompilationUnit(compilationUnit))
        {
            flowScript = null;
            return false;
        }

        flowScript = mScript;

        return true;
    }

    //
    // Compiling compilation units
    //
    private void InitializeCompilationState()
    {
        mScript = new FlowScript(mFormatVersion);
        mNextLabelIndex = 0;

        // Set up scope stack
        mScopeStack = new Stack<ScopeContext>();

        // Create & push root scope
        // This is where all script-level declarations are stored
        mRootScope = new ScopeContext(null);
        mScopeStack.Push(mRootScope);

        mInstrinsic = new IntrinsicSupport(Library);
        if (!mInstrinsic.SupportsTrace)
        {
            Info("Tracing is not supported by the specified library; it will be disabled for the current compilation");
            EnableFunctionCallTracing = EnableProcedureCallTracing = EnableProcedureTracing = EnableStackCookie = false;
        }

        mProcedureInstructionCache = new Dictionary<string, List<Instruction>>();
    }

    // Reorders any procedures with forced indices
    private void ReorderProcedures(CompilationUnit compilationUnit)
    {
        for (int i = 0; i < compilationUnit.Declarations.Count; i++)
        {
            var declaration = compilationUnit.Declarations[i];
            if (declaration.DeclarationType != DeclarationType.Procedure)
                continue;

            var nameParts = declaration.Identifier.Text.Split('_');
            if (nameParts.Length < 2) continue;
            if (!nameParts[nameParts.Length - 2].Equals("index", StringComparison.OrdinalIgnoreCase)) continue;
            if (!int.TryParse(nameParts[nameParts.Length - 1], out var index))
            {
                Error($"Unable to parse procedure index {nameParts[nameParts.Length - 1]}. Index will not be changed");
                continue;
            }

            var procedure = (ProcedureDeclaration)declaration;
            Info($"Changed procedure index of {declaration.Identifier.Text} from {procedure.Index} to {index}");
            ((ProcedureDeclaration)compilationUnit.Declarations[i]).Index = index;
        }
    }

    // Adds dummy procedures if there are any that don't exist due to forced indices
    private void AddMissingProcedures(CompilationUnit compilationUnit)
    {
        int maxIndex = Scope.Procedures.Max(x => x.Value.Index);
        for (int i = 0; i < maxIndex; i++)
        {
            if (!Scope.Procedures.Any(x => x.Value.Index == i))
            {
                // Add dummy procedure
                var procedure = new ProcedureDeclaration(i, TypeIdentifier.Void, new Identifier($"procedure_{i}"), new List<Parameter>(), new CompoundStatement());
                compilationUnit.Declarations.Add(procedure);
                Scope.TryDeclareProcedure(procedure, out _);
            }
        }
    }

    private bool TryCompileCompilationUnit(CompilationUnit compilationUnit)
    {
        Info($"Start compiling FlowScript compilation unit with version {mFormatVersion}");

        // Initialize
        InitializeCompilationState();

        // Resolve imports
        if (compilationUnit.Imports.Count > 0 || mBaseBfImport != (null, null))
        {
            do
            {
                if (!TryResolveImports(compilationUnit))
                {
                    Error(compilationUnit, "Failed to resolve imports");
                    return false;
                }
            } while (mReresolveImports);
        }

        ReorderProcedures(compilationUnit);

        // Evaluate declarations, return values, parameters etc
        if (!TryEvaluateCompilationUnitBeforeCompilation(compilationUnit))
            return false;

        AddMissingProcedures(compilationUnit);

        if (ProcedureHookMode == ProcedureHookMode.ImportedOnly)
        {
            foreach (var proc in mScript.Procedures)
                TryHookProcedure(proc.Name);
        }

        // Compile compilation unit body
        foreach (var statement in compilationUnit.Declarations)
        {
            if (statement is ProcedureDeclaration procedureDeclaration)
            {
                if (procedureDeclaration.Body != null)
                {
                    if (!TryCompileProcedure(procedureDeclaration, out var procedure))
                        return false;

                    // Add compiled procedure
                    AddCompiledProcedure(procedure);
                }
            }
            else if (statement is VariableDeclaration variableDeclaration)
            {
                if (variableDeclaration.Initializer != null)
                {
                    if (variableDeclaration.Modifier == null || variableDeclaration.Modifier.Kind != VariableModifierKind.Constant)
                    {
                        Error(variableDeclaration.Initializer, "Non-constant variables declared outside of a procedure can't be initialized with a value");
                        return false;
                    }
                }
                else
                {
                    if (variableDeclaration.Modifier?.Kind == VariableModifierKind.Constant)
                    {
                        if (variableDeclaration.Initializer == null)
                        {
                            Error(variableDeclaration, "Missing initializer for constant variable");
                            return false;
                        }
                    }
                }
            }
            else if (!(statement is FunctionDeclaration) && !(statement is EnumDeclaration))
            {
                Error(statement, $"Unexpected top-level statement type: {statement}");
                return false;
            }
        }

        if (ProcedureHookMode == ProcedureHookMode.All)
        {
            foreach (var proc in mScript.Procedures)
                TryHookProcedure(proc.Name);
        }

        Info("Done compiling compilation unit");

        return true;
    }

    private void ExpandImportStatementsPaths(CompilationUnit compilationUnit, string baseDirectory)
    {
        foreach (var import in compilationUnit.Imports)
        {
            import.CompilationUnitFileName = Path.Combine(baseDirectory, import.CompilationUnitFileName);
        }
    }

    //
    // Resolving imports
    //
    private bool TryResolveImports(CompilationUnit compilationUnit)
    {
        Info(compilationUnit, "Resolving imports");

        ExpandImportStatementsPaths(compilationUnit, mCurrentBaseDirectory);

        var importedMessageScripts = new List<MessageScript>();
        var importedFlowScripts = new List<CompilationUnit>();
        var importedCompiledFlowScripts = new List<(Import Import, FlowScript Script)>();

        foreach (var import in compilationUnit.Imports)
        {
            var ext = Path.GetExtension(import.CompilationUnitFileName).ToLowerInvariant();

            switch (ext)
            {
                case ".msg":
                    {
                        // MessageScript
                        if (!TryResolveMessageScriptImport(import, out var messageScript))
                        {
                            Error(import, $"Failed to resolve MessageScript import: {import.CompilationUnitFileName}");
                            return false;
                        }

                        // Will be null if it was already imported before
                        if (messageScript != null)
                            importedMessageScripts.Add(messageScript);
                    }
                    break;

                case ".flow":
                    {
                        // FlowScript
                        if (!TryResolveFlowScriptImport(import, out var importedCompilationUnit))
                        {
                            Error(import, $"Failed to resolve FlowScript import: {import.CompilationUnitFileName}");
                            return false;
                        }

                        // Will be null if it was already imported before
                        if (importedCompilationUnit != null)
                            importedFlowScripts.Add(importedCompilationUnit);
                    }
                    break;

                case ".bf":
                    {
                        if (!TryResolveCompiledFlowScriptImport(import, out var importedScript))
                        {
                            Error(import, $"Failed to resolve compiled FlowScript import: {import.CompilationUnitFileName}");
                            return false;
                        }

                        if (importedScript != null)
                            importedCompiledFlowScripts.Add((import, importedScript));
                    }
                    break;

                default:
                    // Unknown
                    Error(import, $"Unknown import file type: {import.CompilationUnitFileName}");
                    return false;

            }
        }

        // process compiled FlowScript imports
        if (mBaseBfImport != (null, null))
        {
            importedCompiledFlowScripts.Add(mBaseBfImport);
            mBaseBfImport = (null, null); // Prevent it from being imported multiple times
        }
        foreach (var compiledFlowScriptImport in importedCompiledFlowScripts)
        {
            var script = compiledFlowScriptImport.Script;
            var import = compiledFlowScriptImport.Import;

            if (!TryProcessCompiledFlowScriptImport(script))
            {
                Error(import, $"Failed to resolve compiled FlowScript import: {import.CompilationUnitFileName}");
                return false;
            }
        }

        // Resolve MessageScripts imports
        if (importedMessageScripts.Count > 0)
        {
            MergeMessageScripts(importedMessageScripts);
        }

        // Resolve FlowScript imports
        bool shouldReresolveImports = false;
        if (importedFlowScripts.Count > 0)
        {
            // Merge compilation units
            foreach (var importedFlowScript in importedFlowScripts)
            {
                if (importedFlowScript.Imports.Count > 0)
                {
                    // If any of the imported FlowScripts have import, we have to re-resolve the imports again
                    shouldReresolveImports = true;
                    compilationUnit.Imports.AddRange(importedFlowScript.Imports);
                }

                compilationUnit.Declarations.AddRange(importedFlowScript.Declarations);
            }
        }

        mReresolveImports = shouldReresolveImports;

        if (!mReresolveImports)
            Info(compilationUnit, "Done resolving imports");

        return true;
    }

    private bool TryProcessCompiledFlowScriptImport(FlowScript compiledFlowScript)
    {
        // Register declarations for procedures declared in the imported script
        for (var i = 0; i < compiledFlowScript.Procedures.Count; i++)
        {
            // Add a declaration for the imported procedure
            var procedure = compiledFlowScript.Procedures[i];
            var procedureDecl = new ProcedureDeclaration(new IntLiteral(i), TypeIdentifier.Void,
                                                          new Identifier(procedure.Name),
                                                          new List<Parameter>(), null);

            Debug.Assert(mScript.Procedures.Count == i, "Imported procedure index mismatch");

            // Add compiled procedure
            if (!Scope.TryDeclareProcedure(procedureDecl, procedure, out var procedureInfo))
                Debug.Assert(false);

            AddCompiledProcedure(procedureInfo, procedure);
        }

        // Add declarations for top-level/global variables
        // TODO: this logic doesn't really belong here
        var varProcedureAccessesMap = new Dictionary<(VariableModifierKind, ValueKind, int), HashSet<FlowScriptLanguage.Procedure>>();
        foreach (var proc in compiledFlowScript.Procedures)
        {
            foreach (var inst in proc.Instructions)
            {
                (VariableModifierKind, ValueKind, int) key;
                switch (inst.Opcode)
                {
                    case Opcode.PUSHIX:
                    case Opcode.POPIX:
                        key = (VariableModifierKind.Global, ValueKind.Int, inst.Operand.Int16Value);
                        break;
                    case Opcode.PUSHIF:
                    case Opcode.POPFX:
                        key = (VariableModifierKind.Global, ValueKind.Float, inst.Operand.Int16Value);
                        break;
                    case Opcode.PUSHLIX:
                    case Opcode.POPLIX:
                        key = (VariableModifierKind.Local, ValueKind.Int, inst.Operand.Int16Value);
                        break;
                    case Opcode.PUSHLFX:
                    case Opcode.POPLFX:
                        key = (VariableModifierKind.Local, ValueKind.Float, inst.Operand.Int16Value);
                        break;
                    default:
                        continue;
                }

                if (!varProcedureAccessesMap.ContainsKey(key)) varProcedureAccessesMap[key] = new HashSet<FlowScriptLanguage.Procedure>();
                varProcedureAccessesMap[key].Add(proc);
            }
        }

        foreach (var kvp in varProcedureAccessesMap)
        {
            (VariableModifierKind modifier, ValueKind valueKind, int index) = kvp.Key;
            if (modifier == VariableModifierKind.Local && kvp.Value.Count <= 1)
            {
                // Only add a declaration for local variables if they're referenced by multiple procedures
                continue;
            }

            // Add variable declaration to script
            var decl = new VariableDeclaration(new VariableModifier(modifier, new IntLiteral(index)),
                new TypeIdentifier(valueKind),
                new Identifier(valueKind, NameFormatter.GenerateVariableName(modifier, valueKind, (short)index, true)),
                null);

            if (!TryRegisterVariableDeclaration(decl, out _, out _))
            {
                Error(decl, $"Duplicate variable declaration: {decl}");
                return false;
            }
            Trace($"Registered imported variable declaration '{decl}'");
        }

        // Set next variable index to past the max. variable indices of the imported scripts
        var maxIntVarIdx = varProcedureAccessesMap.Where(x => x.Key.Item1 == VariableModifierKind.Local && x.Key.Item2 == ValueKind.Int).MaxOrDefault(x => x.Key.Item3, -1);
        var maxFloatVarIdx = varProcedureAccessesMap.Where(x => x.Key.Item1 == VariableModifierKind.Local && x.Key.Item2 == ValueKind.Float).MaxOrDefault(x => x.Key.Item3, -1);
        var maxAiGlobalVarIdx = varProcedureAccessesMap.Where(x => x.Key.Item1 == VariableModifierKind.AiGlobal).MaxOrDefault(x => x.Key.Item3, -1);
        var maxAiLocalVarIdx = varProcedureAccessesMap.Where(x => x.Key.Item1 == VariableModifierKind.AiLocal).MaxOrDefault(x => x.Key.Item3, -1);
        var maxCountVarIdx = varProcedureAccessesMap.Where(x => x.Key.Item1 == VariableModifierKind.Count).MaxOrDefault(x => x.Key.Item3, -1);
        var maxGlobalIntVarIdx = varProcedureAccessesMap.Where(x => x.Key.Item1 == VariableModifierKind.Global && x.Key.Item2 == ValueKind.Int).MaxOrDefault(x => x.Key.Item3, -1);
        var maxGlobalFloatVarIdx = varProcedureAccessesMap.Where(x => x.Key.Item1 == VariableModifierKind.Global && x.Key.Item2 == ValueKind.Float).MaxOrDefault(x => x.Key.Item3, -1);
        var maxLabelIdx = compiledFlowScript.EnumerateInstructions().Where(x => x.Opcode == Opcode.GOTO).MaxOrDefault(x => x.Operand.Int16Value, -1);

        mNextIntVariableIndex = Math.Max(mNextIntVariableIndex, (short)(maxIntVarIdx + 1));
        mNextFloatVariableIndex = Math.Max(mNextFloatVariableIndex, (short)(maxFloatVarIdx + 1));
        mNextAiGlobalVariableIndex = Math.Max(mNextAiGlobalVariableIndex, (short)(maxAiGlobalVarIdx + 1));
        mNextAiLocalVariableIndex = Math.Max(mNextAiLocalVariableIndex, (short)(maxAiLocalVarIdx + 1));
        mNextCounterVariableIndex = Math.Max(mNextCounterVariableIndex, (short)(maxCountVarIdx + 1));
        mNextGlobalIntVariableIndex = Math.Max(mNextGlobalIntVariableIndex, (short)(maxGlobalIntVarIdx + 1));
        mNextGlobalFloatVariableIndex = Math.Max(mNextGlobalFloatVariableIndex, (short)(maxGlobalFloatVarIdx + 1));
        mNextLabelIndex = Math.Max(mNextLabelIndex, maxLabelIdx + 1);

        if (compiledFlowScript.MessageScript != null)
            MergeMessageScript(compiledFlowScript.MessageScript);

        return true;
    }

    private void MergeMessageScripts(List<MessageScript> messageScripts)
    {
        // Merge message scripts
        foreach (var messageScript in messageScripts)
        {
            if (messageScript != null)
                MergeMessageScript(messageScript);
        }
    }

    private void MergeMessageScript(MessageScript messageScript)
    {
        if (messageScript == null)
            throw new ArgumentNullException(nameof(messageScript));

        if (mScript.MessageScript == null)
            mScript.MessageScript = messageScript;
        else
            mScript.MessageScript.Dialogs.AddRange(messageScript.Dialogs);
    }

    private bool TryGetFullImportPath(Import import, out string path)
    {
        var compilationUnitFilePath = import.CompilationUnitFileName;

        if (!File.Exists(compilationUnitFilePath))
        {
            // Retry as relative path if we have a filename
            if (mFilePath != null)
            {
                compilationUnitFilePath = Path.Combine(Path.GetDirectoryName(mFilePath), compilationUnitFilePath);

                if (!File.Exists(compilationUnitFilePath))
                {
                    Error(import, $"File to import does not exist: {import.CompilationUnitFileName}");
                    path = null;
                    return false;
                }
            }
            else
            {
                Error(import, $"File to import does not exist: {import.CompilationUnitFileName}");
                path = null;
                return false;
            }
        }

        path = compilationUnitFilePath;
        return true;
    }

    private bool TryResolveMessageScriptImport(Import import, out MessageScript messageScript)
    {
        Info($"Resolving MessageScript import '{import.CompilationUnitFileName}'");

        var messageScriptCompiler = new MessageScriptCompiler(GetMessageScriptFormatVersion(), Encoding);
        messageScriptCompiler.AddListener(new LoggerPassthroughListener(mLogger));
        messageScriptCompiler.Library = Library;

        if (!TryGetFullImportPath(import, out var compilationUnitFilePath))
        {
            messageScript = null;
            return false;
        }

        Info($"Importing MessageScript from file '{compilationUnitFilePath}'");

        string messageScriptSource;

        try
        {
            messageScriptSource = File.ReadAllText(compilationUnitFilePath);
        }
        catch (Exception)
        {
            Error(import, $"Can't open MessageScript file to import: {import.CompilationUnitFileName}");
            messageScript = null;
            return false;
        }

        int messageScriptSourceHash = messageScriptSource.GetHashCode();

        if (!mImportedFileHashSet.Contains(messageScriptSourceHash))
        {
            if (!messageScriptCompiler.TryCompile(messageScriptSource, out messageScript))
            {
                Error(import, $"Import MessageScript failed to compile: {import.CompilationUnitFileName}");
                return false;
            }

            mImportedFileHashSet.Add(messageScriptSourceHash);
        }
        else
        {
            Warning($"MessageScript file '{compilationUnitFilePath}' was already included once! Skipping!");
            messageScript = null;
        }

        return true;
    }

    private bool TryResolveFlowScriptImport(Import import, out CompilationUnit importedCompilationUnit)
    {
        Info($"Resolving FlowScript import '{import.CompilationUnitFileName}'");

        if (!TryGetFullImportPath(import, out var compilationUnitFilePath))
        {
            importedCompilationUnit = null;
            return false;
        }

        Info($"Importing FlowScript from file '{compilationUnitFilePath}'");
        FileStream flowScriptFileStream;
        try
        {
            flowScriptFileStream = File.Open(compilationUnitFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (Exception)
        {
            Error(import, $"Can't open FlowScript file to import: {import.CompilationUnitFileName}");
            importedCompilationUnit = null;
            return false;
        }

        var hashAlgo = new MD5CryptoServiceProvider();
        var hashBytes = hashAlgo.ComputeHash(flowScriptFileStream);
        int flowScriptSourceHash = BitConverter.ToInt32(hashBytes, 0);
        flowScriptFileStream.Position = 0;

        if (!mImportedFileHashSet.Contains(flowScriptSourceHash))
        {
            var parser = new CompilationUnitParser();
            parser.AddListener(new LoggerPassthroughListener(mLogger));
            if (!parser.TryParse(flowScriptFileStream, out importedCompilationUnit))
            {
                Error(import, "Failed to parse imported FlowScript");
                return false;
            }

            flowScriptFileStream.Dispose();

            ExpandImportStatementsPaths(importedCompilationUnit, Path.GetDirectoryName(compilationUnitFilePath));

            mImportedFileHashSet.Add(flowScriptSourceHash);
        }
        else
        {
            Warning($"FlowScript file '{compilationUnitFilePath}' was already included once! Skipping!");
            importedCompilationUnit = null;
        }

        return true;
    }

    private bool TryResolveCompiledFlowScriptImport(Import import, out FlowScript script)
    {
        Info($"Resolving compiled FlowScript import '{import.CompilationUnitFileName}'");

        if (!TryGetFullImportPath(import, out var compilationUnitFilePath))
        {
            script = null;
            return false;
        }

        Info($"Importing compiled FlowScript from file '{compilationUnitFilePath}'");
        FileStream flowScriptFileStream;
        try
        {
            flowScriptFileStream = File.Open(compilationUnitFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (Exception)
        {
            Error(import, $"Can't open compiled FlowScript file to import: {import.CompilationUnitFileName}");
            script = null;
            return false;
        }

        var hashAlgo = new MD5CryptoServiceProvider();
        var hashBytes = hashAlgo.ComputeHash(flowScriptFileStream);
        int flowScriptSourceHash = BitConverter.ToInt32(hashBytes, 0);
        flowScriptFileStream.Position = 0;

        if (!mImportedFileHashSet.Contains(flowScriptSourceHash))
        {
            try
            {
                script = script = FlowScript.FromStream(flowScriptFileStream, Encoding);
            }
            catch (Exception)
            {
                Error(import, $"Can't open compiled FlowScript file to import: {import.CompilationUnitFileName}");
                script = null;
                return false;
            }

            mImportedFileHashSet.Add(flowScriptSourceHash);
        }
        else
        {
            Warning($"Compiled FlowScript file '{compilationUnitFilePath}' was already included once! Skipping!");
            script = null;
        }

        return true;
    }

    private MessageScriptLanguage.FormatVersion GetMessageScriptFormatVersion()
    {
        switch (mFormatVersion)
        {
            case FormatVersion.Version1:
            case FormatVersion.Version2:
            case FormatVersion.Version3:
                return MessageScriptLanguage.FormatVersion.Version1;
            case FormatVersion.Version1BigEndian:
            case FormatVersion.Version2BigEndian:
            case FormatVersion.Version3BigEndian:
                return MessageScriptLanguage.FormatVersion.Version1BigEndian;
        }

        return MessageScriptLanguage.FormatVersion.Version1;
    }

    private bool TryEvaluateCompilationUnitBeforeCompilation(CompilationUnit compilationUnit)
    {
        // Declare constants for the message script window names
        if (mScript.MessageScript != null)
        {
            Info("Inserting MessageScript window identifier constants");
            for (int i = 0; i < mScript.MessageScript.Dialogs.Count; i++)
            {
                var dialog = mScript.MessageScript.Dialogs[i];

                if (OverwriteExistingMsgs)
                {
                    // Try and replace the current one with the last one
                    int last = mScript.MessageScript.Dialogs.FindLastIndex(msg => msg.Name == dialog.Name);
                    mScript.MessageScript.Dialogs[i] = mScript.MessageScript.Dialogs[last]; // Replace current one
                    dialog = mScript.MessageScript.Dialogs[i];
                    while (last != i) // Keep removing from the end until there's only one
                    {
                        mScript.MessageScript.Dialogs.RemoveAt(last);
                        last = mScript.MessageScript.Dialogs.FindLastIndex(msg => msg.Name == dialog.Name);
                    }
                }

                var declaration = new VariableDeclaration
                (
                    new VariableModifier(VariableModifierKind.Constant),
                    new TypeIdentifier(ValueKind.Int),
                    new Identifier(ValueKind.Int, dialog.Name),
                    new IntLiteral(i)
                );

                if (!Scope.TryDeclareVariable(declaration))
                {
                    Error(declaration, $"Compiler generated constant for MessageScript dialog {dialog.Name} conflicts with another variable");
                }
                else
                {
                    Info($"Declared compile time constant: {declaration}");
                }
            }
        }

        bool hasIntReturnValue = false;
        bool hasFloatReturnValue = false;
        short maxIntParameterCount = 0;
        short maxFloatParameterCount = 0;

        // top-level only
        Trace("Registering script declarations");
        foreach (var statement in compilationUnit.Declarations)
        {
            switch (statement)
            {
                case FunctionDeclaration functionDeclaration:
                    {
                        if (!Scope.TryDeclareFunction(functionDeclaration))
                        {
                            Warning(functionDeclaration, $"Ignoring duplicate function declaration: {functionDeclaration}");
                        }
                        else
                        {
                            Trace($"Registered function declaration '{functionDeclaration}'");
                        }
                    }
                    break;
                case ProcedureDeclaration procedureDeclaration:
                    {
                        if (!Scope.TryDeclareProcedure(procedureDeclaration, out _))
                        {
                            Error(procedureDeclaration, $"Duplicate procedure declaration: {procedureDeclaration}");
                            return false;
                        }

                        Trace($"Registered procedure declaration '{procedureDeclaration}'");

                        if (procedureDeclaration.ReturnType.ValueKind != ValueKind.Void)
                        {
                            if (procedureDeclaration.ReturnType.ValueKind.GetBaseKind() == ValueKind.Int)
                            {
                                hasIntReturnValue = true;
                            }
                            else if (procedureDeclaration.ReturnType.ValueKind == ValueKind.Float)
                            {
                                hasFloatReturnValue = true;
                            }
                        }

                        // Count parameter by type.
                        short intParameterCount = 0;
                        short floatParameterCount = 0;

                        foreach (var parameter in procedureDeclaration.Parameters)
                        {
                            short count = 1;
                            if (parameter.IsArray)
                                count = (short)(((ArrayParameter)parameter).Size);

                            if (parameter.Type.ValueKind.GetBaseKind() == ValueKind.Int)
                                intParameterCount += count;
                            else
                                floatParameterCount += count;
                        }

                        maxIntParameterCount = Math.Max(intParameterCount, maxIntParameterCount);
                        maxFloatParameterCount = Math.Max(floatParameterCount, maxFloatParameterCount);

                        //if ( ProcedureHookMode == ProcedureHookMode.ImportedOnly )
                        //{
                        //    TryHookProcedure( procedureDeclaration.Identifier.Text );
                        //}
                    }
                    break;

                case VariableDeclaration variableDeclaration:
                    {
                        if (!TryRegisterVariableDeclaration(variableDeclaration, out _, out _))
                        {
                            Error(variableDeclaration, $"Duplicate variable declaration: {variableDeclaration}");
                            return false;
                        }
                        Trace($"Registered variable declaration '{variableDeclaration}'");
                    }
                    break;

                case EnumDeclaration enumDeclaration:
                    {
                        if (!Scope.TryDeclareEnum(enumDeclaration))
                        {
                            Error(enumDeclaration, $"Failed to declare enum: {enumDeclaration}");
                            return false;
                        }
                    }
                    break;
            }
        }

            // Add stuff from registry
            if (Library != null)
            {
                // Functions
                foreach (var libraryFunction in Library.FlowScriptModules.SelectMany(x => x.Functions))
                {
                    Scope.TryDeclareFunctions(FunctionDeclaration.FromLibraryFunctionWithAliases(libraryFunction));
                }

            // Enums
            foreach (var libraryEnum in Library.FlowScriptModules
                                                        .Where(x => x.Enums != null)
                                                        .SelectMany(x => x.Enums))
            {
                Scope.TryDeclareEnum(EnumDeclaration.FromLibraryEnum(libraryEnum));
            }

            // Constants
            foreach (var libraryConstant in Library.FlowScriptModules
                                                        .Where(x => x.Constants != null)
                                                        .SelectMany(x => x.Constants))
            {
                Scope.TryDeclareVariable(VariableDeclaration.FromLibraryConstant(libraryConstant));
            }
        }

        // Declare return value variable
        if (hasIntReturnValue)
        {
            mIntReturnValueVariable = Scope.GenerateVariable(ValueKind.Int, mNextIntVariableIndex++);
        }

        if (hasFloatReturnValue)
        {
            mFloatReturnValueVariable = Scope.GenerateVariable(ValueKind.Float, mNextFloatVariableIndex++);
        }


        // Set up indices
        mNextIntArgumentVariableIndex = mNextIntVariableIndex;
        mNextIntVariableIndex += maxIntParameterCount;

        mNextFloatArgumentVariableIndex = mNextFloatVariableIndex;
        mNextFloatVariableIndex += maxFloatParameterCount;

        return true;
    }

    private void TryHookProcedure(string name)
    {
        if (!mRootScope.TryGetProcedure(name, out var procedureInfo) ||
             procedureInfo.Compiled == null)
            return;

        if (mRootScope.TryGetProcedure(name + "_hook", out var hookProcedureInfo))
        {
            Info($"Registering {hookProcedureInfo.Declaration.Identifier.Text} as hook for {name}");
            BackupCompiledProcedure(procedureInfo);

            procedureInfo.Compiled.Instructions.Clear();
            procedureInfo.Compiled.Instructions.Add(Instruction.PROC(procedureInfo.Index));
            procedureInfo.Compiled.Instructions.Add(Instruction.CALL(hookProcedureInfo.Index));
            procedureInfo.Compiled.Instructions.Add(Instruction.END());
        }

        if (mRootScope.TryGetProcedure(name + "_hookafter", out hookProcedureInfo))
        {
            Info($"Registering {hookProcedureInfo.Declaration.Identifier.Text} as hook (after) for {name}");
            BackupCompiledProcedure(procedureInfo);

            // Insert call to hook at every return
            for (int i = 0; i < procedureInfo.Compiled.Instructions.Count; i++)
            {
                if (procedureInfo.Compiled.Instructions[i].Opcode == Opcode.END)
                {
                    procedureInfo.Compiled.Instructions.Insert(i, Instruction.CALL(hookProcedureInfo.Index));
                    i++;
                }
            }
        }

        if (mRootScope.TryGetProcedure(name + "_softhook", out hookProcedureInfo))
        {
            Info($"Registering {hookProcedureInfo.Declaration.Identifier.Text} as hook (after) for {name}");
            BackupCompiledProcedure(procedureInfo);

            // Insert call to hook at start of the procedure without a return
            procedureInfo.Compiled.Instructions.Insert(1, Instruction.CALL(hookProcedureInfo.Index));
        }

        void BackupCompiledProcedure(ProcedureInfo _procedureInfo)
        {
            if (_procedureInfo.OriginalCompiled == null)
                _procedureInfo.OriginalCompiled = _procedureInfo.Compiled.Clone();
        }
    }

    //
    // Procedure code generation
    //
    private void InitializeProcedureCompilationState(ProcedureDeclaration declaration)
    {
        mProcedureDeclaration = declaration;
        mInstructions = new List<Instruction>();
        mLabels = new Dictionary<string, LabelInfo>();
        mStackValueCount = 1;
    }

    private bool TryCompileProcedure(ProcedureDeclaration declaration, out FlowScriptLanguage.Procedure procedure)
    {
        Info(declaration, $"Compiling procedure: {declaration.Identifier.Text}");

        // Initialize procedure to null so we can return without having to set it explicitly
        procedure = null;

        // Compile procedure body
        if (!TryEmitProcedureBody(declaration))
            return false;

        // Create labels
        if (!TryResolveProcedureLabels(out var labels))
            return false;

        // Create the procedure object
        procedure = new FlowScriptLanguage.Procedure(declaration.Identifier.Text, mInstructions, labels);

        return true;
    }

    private bool TryEmitProcedureBody(ProcedureDeclaration declaration)
    {
        Trace(declaration.Body, $"Emitting procedure body for {declaration}");

        var startIntArgumentVariableIndex = mNextIntArgumentVariableIndex;
        var startFloatArgumentVariableIndex = mNextFloatArgumentVariableIndex;

        // Initialize some state
        InitializeProcedureCompilationState(declaration);

        // Emit procedure start  
        PushScope();
        Emit(Instruction.PROC(mRootScope.Procedures[declaration.Identifier.Text].Index));

        if (EnableProcedureTracing)
            TraceProcedureStart();

        if (EnableStackCookie)
        {
            // Emit stack cookie
            Emit(Instruction.PUSHI(declaration.Identifier.Text.GetHashCode()));
        }

        // Register / forward declare labels in procedure body before codegen
        Trace(declaration.Body, "Forward declaring labels in procedure body");
        if (!TryRegisterLabels(declaration.Body))
        {
            Error(declaration.Body, "Failed to forward declare labels in procedure body");
            return false;
        }

        // Emit procedure parameters
        if (declaration.Parameters.Count > 0)
        {
            Trace(declaration, "Emitting code for procedure parameters");
            if (!TryEmitProcedureParameters(declaration.Parameters))
            {
                Error(declaration, "Failed to emit procedure parameters");
                return false;
            }
        }

        ReturnStatement returnStatement = new ReturnStatement();

        // Remove last return statement
        if (declaration.Body.Statements.Count != 0 && declaration.Body.Statements.Last() is ReturnStatement)
        {
            returnStatement = (ReturnStatement)declaration.Body.Last();
            declaration.Body.Statements.Remove(returnStatement);
        }

        // Emit procedure body
        Trace(declaration.Body, "Emitting code for procedure body");
        if (!TryEmitStatements(declaration.Body))
        {
            Error(declaration.Body, "Failed to emit procedure body");
            return false;
        }

        // Assign out parameters
        if (declaration.Parameters.Count > 0)
        {
            var intVariableCount = 0;
            var floatVariableCount = 0;

            foreach (var parameter in declaration.Parameters)
            {
                Scope.TryGetVariable(parameter.Identifier.Text, out var variable);

                if (parameter.Type.ValueKind.GetBaseKind() == ValueKind.Int)
                {
                    if (parameter.Modifier == ParameterModifier.Out)
                    {
                        Emit(Instruction.PUSHLIX(variable.Index));
                        Emit(Instruction.POPLIX((short)(startIntArgumentVariableIndex + intVariableCount)));
                    }

                    ++intVariableCount;
                }
                else
                {
                    if (parameter.Modifier == ParameterModifier.Out)
                    {
                        Emit(Instruction.PUSHLFX(variable.Index));
                        Emit(Instruction.POPLFX((short)(startFloatArgumentVariableIndex + floatVariableCount)));
                    }

                    ++floatVariableCount;
                }
            }
        }

        if (!TryEmitReturnStatement(returnStatement))
        {
            return false;
        }

        PopScope();

        return true;
    }

    private bool TryEmitProcedureParameters(List<Parameter> parameters)
    {
        int intArgumentCount = 0;
        int floatArgumentCount = 0;

        foreach (var parameter in parameters)
        {
            Trace(parameter, $"Emitting parameter: {parameter}");

            // Create declaration
            VariableDeclaration declaration;
            int count = 1;

            if (!parameter.IsArray)
            {
                declaration = new VariableDeclaration(
                    new VariableModifier(VariableModifierKind.Local),
                    parameter.Type,
                    parameter.Identifier,
                    null);
            }
            else
            {
                count = ((ArrayParameter)parameter).Size;

                declaration = new ArrayVariableDeclaration(
                    new VariableModifier(VariableModifierKind.Local),
                    parameter.Type,
                    parameter.Identifier,
                    count,
                    null);
            }

            // Declare variable
            if (!TryEmitVariableDeclaration(declaration, out var index))
                return false;

            // Push argument value
            for (int i = 0; i < count; i++)
            {
                if (declaration.Type.ValueKind.GetBaseKind() == ValueKind.Int)
                {
                    if (parameter.Modifier != ParameterModifier.Out)
                        Emit(Instruction.PUSHLIX(mNextIntArgumentVariableIndex));

                    ++mNextIntArgumentVariableIndex;
                    ++intArgumentCount;
                }
                else
                {
                    if (parameter.Modifier != ParameterModifier.Out)
                        Emit(Instruction.PUSHLFX(mNextFloatArgumentVariableIndex));

                    ++mNextFloatArgumentVariableIndex;
                    ++floatArgumentCount;
                }

                if (parameter.Modifier != ParameterModifier.Out)
                {
                    // Assign parameter with argument value
                    if (!TryEmitVariableAssignment(declaration, (short)(index + i)))
                        return false;
                }
            }
        }

        // Reset parameter indices
        mNextIntArgumentVariableIndex -= (short)intArgumentCount;
        mNextFloatArgumentVariableIndex -= (short)floatArgumentCount;

        return true;
    }

    private bool TryRegisterLabels(CompoundStatement body)
    {
        foreach (var declaration in body.Select(x => x as Declaration).Where(x => x != null))
        {
            if (declaration.DeclarationType == DeclarationType.Label)
            {
                mLabels[declaration.Identifier.Text] = CreateLabel(declaration.Identifier.Text);
            }
        }

        foreach (var statement in body)
        {
            switch (statement)
            {
                case IfStatement ifStatement:
                    if (!TryRegisterLabels(ifStatement.Body))
                        return false;

                    if (ifStatement.ElseBody != null)
                    {
                        if (!TryRegisterLabels(ifStatement.ElseBody))
                            return false;
                    }
                    break;

                default:
                    break;
            }
        }

        return true;
    }

    private bool TryResolveProcedureLabels(out List<FlowScriptLanguage.Label> labels)
    {
        Trace("Resolving labels in procedure");
        if (mLabels.Values.Any(x => !x.IsResolved))
        {
            foreach (var item in mLabels.Values.Where(x => !x.IsResolved))
                mLogger.Error($"Label '{item.Name}' is referenced but not declared");

            mLogger.Error("Failed to compile procedure because one or more undeclared labels are referenced");
            labels = null;
            return false;
        }

        labels = mLabels.Values
            .Select(x => new FlowScriptLanguage.Label(x.Name, x.InstructionIndex))
            .ToList();

        mLabels.Clear();
        return true;
    }

    //
    // Statements
    //
    private bool TryEmitStatements(IEnumerable<Statement> statements)
    {
        foreach (var statement in statements)
        {
            if (!TryEmitStatement(statement))
                return false;
        }

        return true;
    }

    private bool TryEmitCompoundStatement(CompoundStatement compoundStatement)
    {
        PushScope();

        if (!TryEmitStatements(compoundStatement))
            return false;

        PopScope();

        return true;
    }

    private bool TryEmitStatement(Statement statement)
    {
        switch (statement)
        {
            case CompoundStatement compoundStatement:
                if (!TryEmitCompoundStatement(compoundStatement))
                    return false;
                break;
            case Declaration _:
                {
                    if (statement is VariableDeclaration variableDeclaration)
                    {
                        if (!TryEmitVariableDeclaration(variableDeclaration, out _))
                            return false;
                    }
                    else if (statement is LabelDeclaration labelDeclaration)
                    {
                        if (!TryRegisterLabelDeclaration(labelDeclaration))
                            return false;
                    }
                    else
                    {
                        Error(statement, "Expected variable or label declaration");
                        return false;
                    }

                    break;
                }

            case Expression expression:
                if (!TryEmitExpression(expression, true))
                    return false;
                break;
            case IfStatement ifStatement:
                if (!TryEmitIfStatement(ifStatement))
                    return false;
                break;
            case ForStatement forStatement:
                if (!TryEmitForStatement(forStatement))
                    return false;
                break;
            case WhileStatement whileStatement:
                if (!TryEmitWhileStatement(whileStatement))
                    return false;
                break;
            case BreakStatement breakStatement:
                if (!TryEmitBreakStatement(breakStatement))
                    return false;
                break;
            case ContinueStatement continueStatement:
                if (!TryEmitContinueStatement(continueStatement))
                    return false;
                break;
            case ReturnStatement returnStatement:
                if (!TryEmitReturnStatement(returnStatement))
                {
                    Error(returnStatement, $"Failed to compile return statement: {returnStatement}");
                    return false;
                }

                break;
            case GotoStatement gotoStatement:
                if (!TryEmitGotoStatement(gotoStatement))
                {
                    Error(gotoStatement, $"Failed to compile goto statement: {gotoStatement}");
                    return false;
                }

                break;
            case SwitchStatement switchStatement:
                if (!TryEmitSwitchStatement(switchStatement))
                {
                    Error(switchStatement, $"Failed to compile switch statement: {switchStatement}");
                    return false;
                }

                break;
            default:
                Error(statement, $"Compiling statement '{statement}' not implemented");
                return false;
        }

        return true;
    }

    //
    // Variable stuff
    //        
    private bool TryGetVariableIndex(VariableDeclaration declaration, out short variableIndex)
    {
        short count = 1;
        if (declaration.IsArray)
            count = (short)(((ArrayVariableDeclaration)declaration).Size);

        if (declaration.Modifier == null || declaration.Modifier.Kind == VariableModifierKind.Local)
        {
            if (declaration.Modifier?.Index == null)
            {
                // Local variable
                if (declaration.Type.ValueKind == ValueKind.Float)
                {
                    variableIndex = mNextFloatVariableIndex;
                    mNextFloatVariableIndex += count;
                }
                else
                {
                    variableIndex = mNextIntVariableIndex;
                    mNextIntVariableIndex += count;
                }
            }
            else
            {
                variableIndex = (short)declaration.Modifier.Index.Value;
            }
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Global)
        {
            if (declaration.Modifier.Index == null)
            {
                // Static variable
                // We count the indices for the static variables *down* to
                // to reduce the chance we conflict with the game's original scripts
                if (declaration.Type.ValueKind == ValueKind.Float)
                {
                    variableIndex = mNextGlobalFloatVariableIndex;
                    mNextGlobalFloatVariableIndex -= count;
                }
                else
                {
                    variableIndex = mNextGlobalIntVariableIndex;
                    mNextGlobalIntVariableIndex -= count;
                }
            }
            else
            {
                variableIndex = (short)declaration.Modifier.Index.Value;
            }
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Constant)
        {
            // Constant
            variableIndex = -1;
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.AiLocal)
        {
            if (!mInstrinsic.SupportsAiLocal)
            {
                Error(declaration.Modifier, "ai_local modifier is not supported by the specified library");
                variableIndex = -1;
                return false;
            }

            if (declaration.Modifier.Index == null)
            {
                variableIndex = mNextAiLocalVariableIndex;
                mNextAiLocalVariableIndex += count;
            }
            else
            {
                variableIndex = (short)declaration.Modifier.Index.Value;
            }
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.AiGlobal)
        {
            if (!mInstrinsic.SupportsAiGlobal)
            {
                Error(declaration.Modifier, "ai_global modifier is not supported by the specified library");
                variableIndex = -1;
                return false;
            }

            if (declaration.Modifier.Index == null)
            {
                variableIndex = mNextAiGlobalVariableIndex;
                mNextAiGlobalVariableIndex += count;
            }
            else
            {
                variableIndex = (short)declaration.Modifier.Index.Value;
            }
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Bit)
        {
            if (!mInstrinsic.SupportsBit)
            {
                Error(declaration.Modifier, "bit modifier is not supported by the specified library");
                variableIndex = -1;
                return false;
            }

            variableIndex = (short)declaration.Modifier.Index.Value;
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Count)
        {
            if (!mInstrinsic.SupportsCount)
            {
                Error(declaration.Modifier, "count modifier is not supported by the specified library");
                variableIndex = -1;
                return false;
            }

            variableIndex = (short)declaration.Modifier.Index.Value;
        }
        else
        {
            Error(declaration.Modifier, $"Unexpected variable modifier: {declaration.Modifier}");
            variableIndex = -1;
            return false;
        }

        return true;
    }

    private bool TryRegisterVariableDeclaration(VariableDeclaration declaration, out short index, out bool byReference)
    {
        Trace(declaration, $"Registering variable declaration: {declaration}");

        // Get variable index
        byReference = false;
        index = -1;
        if (declaration.IsArray && declaration.Initializer != null)
        {
            var identifier = declaration.Initializer as Identifier;
            if (identifier != null && Scope.TryGetVariable(identifier.Text, out var variable) && variable.Declaration.IsArray)
            {
                byReference = true;
                index = variable.Index;
            }
        }

        if (!byReference)
        {
            if (!TryGetVariableIndex(declaration, out index))
            {
                Error(declaration, $"Failed to get index for variable '{declaration}'");
                return false;
            }
        }

        // Declare variable in scope
        short size = 1;
        if (declaration.IsArray)
            size = (short)(((ArrayVariableDeclaration)declaration).Size);

        if (!Scope.TryDeclareVariable(declaration, index, size))
        {
            Error(declaration, $"Variable '{declaration}' has already been declared");
            return false;
        }

        return true;
    }

    private bool TryEmitVariableDeclaration(VariableDeclaration declaration, out short index)
    {
        Trace(declaration, $"Emitting variable declaration: {declaration}");

        // Register variable
        if (!TryRegisterVariableDeclaration(declaration, out index, out var byReference))
        {
            Error(declaration, "Failed to register variable declaration");
            index = -1;
            return false;
        }

        // Nothing to emit for constants
        if (declaration.Modifier.Kind == VariableModifierKind.Constant)
        {
            index = -1;
            return true;
        }

        // Emit the variable initializer if it has one         
        if (!byReference && declaration.Initializer != null)
        {
            Trace(declaration.Initializer, "Emitting variable initializer");

            if (!TryEmitVariableAssignment(declaration.Identifier, declaration.Initializer, true))
            {
                Error(declaration.Initializer, "Failed to emit code for variable initializer");
                index = -1;
                return false;
            }
        }

        return true;
    }

    private bool TryRegisterLabelDeclaration(LabelDeclaration declaration)
    {
        Trace(declaration, $"Registering label declaration: {declaration}");

        // register label
        if (!mLabels.TryGetValue(declaration.Identifier.Text, out var label))
        {
            Error(declaration.Identifier, $"Unexpected declaration of an registered label: '{declaration}'");
            return false;
        }

        ResolveLabel(label);

        return true;
    }

    //
    // Expressions
    //
    private bool TryEmitExpression(Expression expression, bool isStatement)
    {
        switch (expression)
        {
            case SubscriptOperator subscriptOperator:
                {
                    if (isStatement)
                    {
                        Error(subscriptOperator, "A subscript is an invalid statement");
                        return false;
                    }

                    if (!TryEmitSubscriptOperator(subscriptOperator))
                        return false;
                }
                break;

            case MemberAccessExpression memberAccessExpression:
                if (isStatement)
                {
                    Error(memberAccessExpression, "A member access is an invalid statement");
                    return false;
                }

                if (!TryEmitMemberAccess(memberAccessExpression))
                    return false;
                break;

            case CallOperator callExpression:
                if (!TryEmitCall(callExpression, isStatement))
                    return false;
                break;
            case UnaryExpression unaryExpression:
                if (!TryEmitUnaryExpression(unaryExpression, isStatement))
                    return false;
                break;
            case BinaryExpression binaryExpression:
                if (!TryEmitBinaryExpression(binaryExpression, isStatement))
                    return false;
                break;
            case Identifier identifier:
                if (isStatement)
                {
                    Error(identifier, "An identifier is an invalid statement");
                    return false;
                }

                if (!TryEmitPushVariableValue(identifier))
                    return false;
                break;
            case BoolLiteral boolLiteral:
                if (isStatement)
                {
                    Error(boolLiteral, "A boolean literal is an invalid statement");
                    return false;
                }

                EmitPushBoolLiteral(boolLiteral);
                break;
            case IntLiteral intLiteral:
                if (isStatement)
                {
                    Error(intLiteral, "A integer literal is an invalid statement");
                    return false;
                }

                EmitPushIntLiteral(intLiteral);
                break;
            case FloatLiteral floatLiteral:
                if (isStatement)
                {
                    Error(floatLiteral, "A float literal is an invalid statement");
                    return false;
                }

                EmitPushFloatLiteral(floatLiteral);
                break;
            case StringLiteral stringLiteral:
                if (isStatement)
                {
                    Error(stringLiteral, "A string literal is an invalid statement");
                    return false;
                }

                EmitPushStringLiteral(stringLiteral);
                break;
            default:
                Error(expression, $"Compiling expression '{expression}' not implemented");
                return false;
        }

        return true;
    }

    private bool TryEmitSubscriptOperator(SubscriptOperator subscriptOperator)
    {
        Trace(subscriptOperator, $"Emitting subscript '{subscriptOperator}'");

        if (!Scope.TryGetVariable(subscriptOperator.Operand.Text, out var variable))
        {
            Error($"Referenced undeclared variable '{subscriptOperator.Operand.Text}'");
            return false;
        }

        if (!variable.Declaration.IsArray)
        {
            Error($"Subscript operator is not valid for non-array variables: '{subscriptOperator}'");
            return false;
        }

        InitializerList arrayInitializer = variable.Declaration.Initializer as InitializerList;

        if (subscriptOperator.Index is IntLiteral intLiteral)
        {
            // Known index
            Expression initializer = null;
            if (arrayInitializer != null)
                initializer = arrayInitializer.Expressions[intLiteral];

            if (!TryEmitPushVariableValue(variable.Declaration.Modifier, variable.Declaration.Type.ValueKind,
                                            variable.GetArrayElementIndex(intLiteral),
                                            initializer))
            {
                return false;
            }
        }
        else
        {
            // Unknown index
            // Start emitting subscript code
            var endLabel = CreateLabel($"SubscriptEndLabel");
            for (int i = 0; i < variable.Size; i++)
            {
                var falseLabel = CreateLabel($"SubscriptIfNot{i}");

                // Emit current index
                EmitPushIntLiteral(i);

                // Emit index expression
                if (!TryEmitExpression(subscriptOperator.Index, false))
                    return false;

                // Emit equals instruction (index == i)
                Emit(Instruction.EQ());

                // Check if index == i
                Emit(Instruction.IF(falseLabel.Index));
                {
                    // Fetch initializer from array initializer if one was supplied
                    Expression initializer = null;
                    if (arrayInitializer != null)
                    {
                        initializer = arrayInitializer.Expressions[i];
                    }

                    // Push the value of array[index]
                    if (!TryEmitPushVariableValue(variable.Declaration.Modifier, variable.Declaration.Type.ValueKind, variable.GetArrayElementIndex(i),
                                                    initializer))
                    {
                        return false;
                    }

                    // Jump to the end of the subscript code
                    Emit(Instruction.GOTO(endLabel.Index));
                }

                // Resolve the label for when the condition is not met
                ResolveLabel(falseLabel);
            }

            // Resolve the end of the subscript code label
            ResolveLabel(endLabel);
        }

        return true;
    }

    private bool TryEmitMemberAccess(MemberAccessExpression memberAccessExpression)
    {
        Trace(memberAccessExpression, $"Emitting member access '{memberAccessExpression}'");

        if (!Scope.TryGetEnum(memberAccessExpression.Operand.Text, out var enumType))
        {
            Error($"Referenced undeclared enum '{memberAccessExpression.Operand.Text}'");
            return false;
        }

        if (!enumType.Members.TryGetValue(memberAccessExpression.Member.Text, out var value))
        {
            Error($"Referenced undeclared enum member '{memberAccessExpression.Member.Text}' in enum '{memberAccessExpression.Operand.Text}'");
            return false;
        }

        if (!TryEmitExpression(value, false))
        {
            Error($"Failed to emit enum value '{value}'");
            return false;
        }

        return true;
    }

    private bool TryEmitCall(CallOperator callExpression, bool isStatement)
    {
        Trace(callExpression, $"Emitting call: {callExpression}");

            if (mRootScope.TryGetFunction(callExpression.Identifier.Text, out var function))
            {
                var libFunc = Library.FlowScriptModules.SelectMany(x => x.Functions).FirstOrDefault(x => x.Name == function.Declaration.Identifier.Text || (x.Aliases != null && x.Aliases.Contains(function.Declaration.Identifier.Text)));

            // Add default values
            var foundDefaultValue = false;
            for (var i = 0; i < function.Declaration.Parameters.Count; i++)
            {
                var param = function.Declaration.Parameters[i];
                if (param.DefaultVaue == null)
                {
                    if (foundDefaultValue)
                    {
                        Error($"Invalid library function definition: found parameter without default value after parameter with default value");
                        return false;
                    }
                }
                else
                {
                    // Insert default values
                    foundDefaultValue = true;

                    if (i + 1 > callExpression.Arguments.Count)
                    {
                        // Add default value if not explicitly specified
                        callExpression.Arguments.Add(new Argument(param.DefaultVaue));
                    }
                }
            }

            if (callExpression.Arguments.Count != function.Declaration.Parameters.Count)
            {
                // Check if function is marked variadic
                if (libFunc == null || libFunc.Semantic != FlowScriptModuleFunctionSemantic.Variadic)
                {
                    Error($"Function '{function.Declaration}' expects {function.Declaration.Parameters.Count} arguments but {callExpression.Arguments.Count} are given");
                    return false;
                }
            }

            // Check MessageScript function call semantics
            if (mScript.MessageScript != null && libFunc != null)
            {
                for (int i = 0; i < libFunc.Parameters.Count; i++)
                {
                    var semantic = libFunc.Parameters[i].Semantic;
                    if (semantic != FlowScriptModuleParameterSemantic.MsgId &&
                         semantic != FlowScriptModuleParameterSemantic.SelId)
                        continue;

                    var arg = callExpression.Arguments[i];
                    if (!(arg.Expression is IntLiteral argInt))
                    {
                        // only check constants for now
                        // TODO: evaluate expressions
                        continue;
                    }

                    var index = argInt.Value;
                    if (index < 0 || index >= mScript.MessageScript.Dialogs.Count)
                    {
                        Error($"Function call to {callExpression.Identifier.Text} references dialog that doesn't exist (index: {index})");
                        return false;
                    }

                    var expectedDialogKind = semantic == FlowScriptModuleParameterSemantic.MsgId
                        ? DialogKind.Message
                        : DialogKind.Selection;

                    var dialog = mScript.MessageScript.Dialogs[index];
                    if (dialog.Kind != expectedDialogKind)
                    {
                        Error($"Function call to {callExpression.Identifier.Text} doesn't reference a {expectedDialogKind} dialog, got dialog of type: {dialog.Kind} index: {index}");
                        return false;
                    }
                }
            }

            if (EnableFunctionCallTracing)
            {
                TraceFunctionCall(function.Declaration);
            }

            if (function.Declaration.Parameters.Count > 0)
            {
                if (!TryEmitFunctionCallArguments(callExpression))
                    return false;
            }

            // call function
            Emit(Instruction.COMM(function.Index));

            if (!isStatement)
            {
                if (function.Declaration.ReturnType.ValueKind == ValueKind.Void)
                {
                    Error(callExpression, $"Void-returning function '{function.Declaration}' used in expression");
                    return false;
                }

                if (!EnableFunctionCallTracing)
                {
                    // push return value of function
                    Trace(callExpression, $"Emitting PUSHREG for {callExpression}");
                    Emit(Instruction.PUSHREG());
                }
                else
                {
                    TraceFunctionCallReturnValue(function.Declaration);
                }
            }
        }
        else if (mRootScope.TryGetProcedure(callExpression.Identifier.Text, out var procedure))
        {
            if (!TryEmitProcedureCall(callExpression, isStatement, procedure))
                return false;
        }
        else if (ProcedureHookMode != ProcedureHookMode.None
            && callExpression.Identifier.Text.IndexOf("_unhooked") != -1 &&
            mRootScope.TryGetProcedure(callExpression.Identifier.Text.Substring(0,
                callExpression.Identifier.Text.IndexOf("_unhooked")), out procedure))
        {
            // copy compiled procedure
            if (procedure.OriginalCompiled == null)
                procedure.OriginalCompiled = procedure.Compiled.Clone();

            var procedureCopy = new Procedure(callExpression.Identifier.Text,
                procedure.OriginalCompiled.Instructions,
                procedure.OriginalCompiled.Labels);

            // copy declaration
            var procedureCopyDecl = new ProcedureDeclaration(
                null,
                procedure.Declaration.ReturnType,
                new Identifier(ValueKind.Procedure, procedureCopy.Name),
                procedure.Declaration.Parameters,
                procedure.Declaration.Body);

            // declare copy
            if (!mRootScope.TryDeclareProcedure(procedureCopyDecl, procedureCopy, out procedure))
                return false;

            // add to compiled script
            AddCompiledProcedure(procedure, procedureCopy);

            // call copy
            if (!TryEmitProcedureCall(callExpression, isStatement, procedure))
                return false;
        }
        else
        {
            Error(callExpression, $"Invalid call expression. Expected function or procedure identifier, got: {callExpression.Identifier}");
            return false;
        }

        return true;
    }

    private void AddCompiledProcedure(Procedure compiledProcedure)
    {
        mRootScope.TryGetProcedure(compiledProcedure.Name, out var procedureInfo);
        AddCompiledProcedure(procedureInfo, compiledProcedure);
    }

    private void AddCompiledProcedure(ProcedureInfo procedure, Procedure compiledProcedure)
    {
        while (procedure.Index >= mScript.Procedures.Count)
            mScript.Procedures.Add(null);

        mScript.Procedures[procedure.Index] = compiledProcedure;
        procedure.Compiled = compiledProcedure;
    }

    private bool TryEmitProcedureCall(CallOperator callExpression, bool isStatement, ProcedureInfo procedure)
    {
        if (callExpression.Arguments.Count != procedure.Declaration.Parameters.Count)
        {
            Error($"Procedure '{procedure.Declaration}' expects {procedure.Declaration.Parameters.Count} arguments but {callExpression.Arguments.Count} are given");
            return false;
        }

        if (EnableProcedureCallTracing)
        {
            TraceProcedureCall(procedure.Declaration);
        }

        if (!TryEmitParameterCallArguments(callExpression, procedure.Declaration, out var parameterIndices))
            return false;

        // call procedure
        Emit(Instruction.CALL(procedure.Index));

        // Emit out parameter assignments
        for (int i = 0; i < procedure.Declaration.Parameters.Count; i++)
        {
            var parameter = procedure.Declaration.Parameters[i];
            if (parameter.Modifier != ParameterModifier.Out)
                continue;

            // Copy value of local variable copy of out parameter to actual out parameter
            var index = parameterIndices[i];
            var identifier = (Identifier)callExpression.Arguments[i].Expression;
            if (!Scope.TryGetVariable(identifier.Text, out var variable))
                return false;

            if (variable.Declaration.Type.ValueKind.GetBaseKind() == ValueKind.Int)
            {
                Emit(Instruction.PUSHLIX(index));
                Emit(Instruction.POPLIX(variable.Index));
            }
            else
            {
                Emit(Instruction.PUSHLFX(index));
                Emit(Instruction.POPLFX(variable.Index));
            }

        }

        // Emit return value
        if (!isStatement)
        {
            if (procedure.Declaration.ReturnType.ValueKind == ValueKind.Void)
            {
                Error($"Void-returning procedure '{procedure.Declaration}' used in expression");
                return false;
            }

            if (!EnableProcedureCallTracing)
            {
                // Push return value of procedure
                if (procedure.Declaration.ReturnType.ValueKind.GetBaseKind() == ValueKind.Int)
                    Emit(Instruction.PUSHLIX(mIntReturnValueVariable.Index));
                else
                    Emit(Instruction.PUSHLFX(mFloatReturnValueVariable.Index));
            }
            else
            {
                TraceProcedureCallReturnValue(procedure.Declaration);
            }
        }

        return true;
    }

    private bool TryEmitFunctionCallArguments(CallOperator callExpression)
    {
        Trace("Emitting function call arguments");

        // Compile expressions backwards so they are pushed to the stack in the right order
        for (int i = callExpression.Arguments.Count - 1; i >= 0; i--)
        {
            if (!TryEmitExpression(callExpression.Arguments[i].Expression, false))
            {
                Error(callExpression.Arguments[i], $"Failed to compile function call argument: {callExpression.Arguments[i]}");
                return false;
            }
        }

        return true;
    }

    private bool TryEmitParameterCallArguments(CallOperator callExpression, ProcedureDeclaration declaration, out List<short> argumentIndices)
    {
        Trace("Emitting parameter call arguments");

        int intArgumentCount = 0;
        int floatArgumentCount = 0;
        argumentIndices = new List<short>();

        for (int i = 0; i < callExpression.Arguments.Count; i++)
        {
            var argument = callExpression.Arguments[i];
            var parameter = declaration.Parameters[i];

            if (!parameter.IsArray)
            {
                if (argument.Modifier != ArgumentModifier.Out)
                {
                    if (!TryEmitExpression(argument.Expression, false))
                    {
                        Error(callExpression.Arguments[i], $"Failed to compile function call argument: {argument}");
                        return false;
                    }
                }

                // Assign each required argument variable
                if (parameter.Type.ValueKind.GetBaseKind() == ValueKind.Int)
                {
                    if (argument.Modifier != ArgumentModifier.Out)
                        Emit(Instruction.POPLIX(mNextIntArgumentVariableIndex));

                    argumentIndices.Add(mNextIntArgumentVariableIndex);

                    ++mNextIntArgumentVariableIndex;
                    ++intArgumentCount;
                }
                else
                {
                    if (argument.Modifier != ArgumentModifier.Out)
                        Emit(Instruction.POPLFX(mNextFloatArgumentVariableIndex));

                    argumentIndices.Add(mNextFloatArgumentVariableIndex);

                    ++mNextFloatArgumentVariableIndex;
                    ++floatArgumentCount;
                }
            }
            else
            {
                var identifier = argument.Expression as Identifier;
                if (identifier == null)
                {
                    Error(argument, "Expected array variable identifier");
                    return false;
                }

                if (!Scope.TryGetVariable(identifier.Text, out var variable))
                {
                    Error(argument, $"Referenced undefined variable: {variable}");
                    return false;
                }

                if (!variable.Declaration.IsArray)
                {
                    Error(argument, "Expected array variable");
                    return false;
                }

                // Copy array
                var count = ((ArrayParameter)parameter).Size;
                for (int j = 0; j < count; j++)
                {
                    if (argument.Modifier != ArgumentModifier.Out)
                    {
                        if (!TryEmitPushVariableValue(variable.Declaration.Modifier, variable.Declaration.Type.ValueKind, variable.GetArrayElementIndex(j), null))
                        {
                            Error(callExpression.Arguments[i], $"Failed to compile function call argument: {argument}");
                            return false;
                        }
                    }

                    // Assign each required argument array variable, essentially copying the entire array
                    if (parameter.Type.ValueKind.GetBaseKind() == ValueKind.Int)
                    {
                        if (argument.Modifier != ArgumentModifier.Out)
                            Emit(Instruction.POPLIX(mNextIntArgumentVariableIndex));

                        if (j == 0)
                            argumentIndices.Add(mNextIntArgumentVariableIndex);

                        ++mNextIntArgumentVariableIndex;
                        ++intArgumentCount;
                    }
                    else
                    {
                        if (argument.Modifier != ArgumentModifier.Out)
                            Emit(Instruction.POPLFX(mNextFloatArgumentVariableIndex));

                        if (j == 0)
                            argumentIndices.Add(mNextFloatArgumentVariableIndex);

                        ++mNextFloatArgumentVariableIndex;
                        ++floatArgumentCount;
                    }
                }
            }
        }

        // Reset the parameter variable indices
        mNextIntArgumentVariableIndex -= (short)intArgumentCount;
        mNextFloatArgumentVariableIndex -= (short)floatArgumentCount;

        return true;
    }

    private bool TryEmitUnaryExpression(UnaryExpression unaryExpression, bool isStatement)
    {
        Trace(unaryExpression, $"Emitting unary expression: {unaryExpression}");

        switch (unaryExpression)
        {
            case PostfixOperator postfixOperator:
                if (!TryEmitPostfixOperator(postfixOperator, isStatement))
                {
                    Error(postfixOperator, "Failed to emit postfix operator");
                    return false;
                }
                break;

            case PrefixOperator prefixOperator:
                if (!TryEmitPrefixOperator(prefixOperator, isStatement))
                {
                    Error(prefixOperator, "Failed to emit prefix operator");
                    return false;
                }
                break;

            default:
                Error(unaryExpression, $"Emitting unary expression '{unaryExpression}' not implemented");
                return false;
        }

        return true;
    }

    private bool TryEmitPostfixOperator(PostfixOperator postfixOperator, bool isStatement)
    {
        var identifier = (Identifier)postfixOperator.Operand;
        if (!Scope.TryGetVariable(identifier.Text, out var variable))
        {
            Error(identifier, $"Reference to undefined variable: {identifier}");
            return false;
        }

        short index;
        if (variable.Declaration.Type.ValueKind != ValueKind.Float)
        {
            index = mNextIntVariableIndex++;
        }
        else
        {
            index = mNextFloatVariableIndex++;
        }

        VariableInfo copy = null;
        if (!isStatement)
        {
            // Make copy of variable
            copy = Scope.GenerateVariable(variable.Declaration.Type.ValueKind, index);

            // Push value of the variable to save in the copy
            if (!TryEmitPushVariableValue(identifier))
            {
                Error(identifier, $"Failed to push variable value to copy variable: {identifier}");
                return false;
            }

            // Assign the copy with the value of the variable
            if (!TryEmitVariableAssignment(copy.Declaration.Identifier))
            {
                Error($"Failed to emit variable assignment to copy variable: {copy}");
                return false;
            }
        }

        // In/decrement the actual variable
        {
            // Push 1
            Emit(Instruction.PUSHIS(1));

            // Push value of the variable
            if (!TryEmitPushVariableValue(identifier))
            {
                Error(identifier, $"Failed to push variable value to copy variable: {identifier}");
                return false;
            }

            // Subtract or add
            if (postfixOperator is PostfixDecrementOperator)
            {
                Emit(Instruction.SUB());
            }
            else if (postfixOperator is PostfixIncrementOperator)
            {
                Emit(Instruction.ADD());
            }
            else
            {
                return false;
            }

            // Emit assignment with calculated value
            if (!TryEmitVariableAssignment(identifier))
            {
                Error(identifier, $"Failed to emit variable assignment: {identifier}");
                return false;
            }
        }

        if (!isStatement)
        {
            // Push the value of the copy
            Trace($"Pushing variable value: {copy.Declaration.Identifier}");

            if (!TryEmitPushVariableValue(copy.Declaration.Identifier))
            {
                Error($"Failed to push value for copy variable {copy}");
                return false;
            }
        }

        return true;
    }

    private bool TryEmitPrefixOperator(PrefixOperator prefixOperator, bool isStatement)
    {
        switch (prefixOperator)
        {
            case LogicalNotOperator _:
            case NegationOperator _:
                if (isStatement)
                {
                    Error(prefixOperator, "A logical not operator is an invalid statement");
                    return false;
                }

                if (!TryEmitExpression(prefixOperator.Operand, false))
                {
                    Error(prefixOperator.Operand, "Failed to emit operand for unary expression");
                    return false;
                }

                if (prefixOperator is LogicalNotOperator)
                {
                    Trace(prefixOperator, "Emitting NOT");
                    Emit(Instruction.NOT());
                }
                else if (prefixOperator is NegationOperator)
                {
                    Trace(prefixOperator, "Emitting MINUS");
                    Emit(Instruction.MINUS());
                }
                else
                {
                    goto default;
                }
                break;

            case PrefixDecrementOperator _:
            case PrefixIncrementOperator _:
                {
                    // Push 1
                    Emit(Instruction.PUSHIS(1));

                    // Push value
                    var identifier = (Identifier)prefixOperator.Operand;
                    if (!TryEmitPushVariableValue(identifier))
                    {
                        Error(identifier, $"Failed to emit variable value for: {identifier}");
                        return false;
                    }

                    // Emit operation
                    if (prefixOperator is PrefixDecrementOperator)
                    {
                        Emit(Instruction.SUB());
                    }
                    else if (prefixOperator is PrefixIncrementOperator)
                    {
                        Emit(Instruction.ADD());
                    }
                    else
                    {
                        goto default;
                    }

                    // Emit assignment
                    if (!TryEmitVariableAssignment(identifier))
                    {
                        Error(prefixOperator, $"Failed to emit variable assignment: {prefixOperator}");
                        return false;
                    }

                    if (!isStatement)
                    {
                        Trace(prefixOperator, $"Emitting variable value: {identifier}");

                        if (!TryEmitPushVariableValue(identifier))
                        {
                            Error(identifier, $"Failed to emit variable value for: {identifier}");
                            return false;
                        }
                    }
                }
                break;

            default:
                Error(prefixOperator, $"Unknown prefix operator: {prefixOperator}");
                return false;
        }

        return true;
    }

    private bool TryEmitBinaryExpression(BinaryExpression binaryExpression, bool isStatement)
    {
        Trace(binaryExpression, $"Emitting binary expression: {binaryExpression}");

        if (binaryExpression is AssignmentOperatorBase assignment)
        {
            if (!TryEmitVariableAssignmentBase(assignment, isStatement))
            {
                Error(assignment, $"Failed to emit variable assignment: {assignment}");
                return false;
            }
        }
        else
        {
            if (isStatement)
            {
                Error(binaryExpression, "A binary operator is not a valid statement");
                return false;
            }

            Trace("Emitting value for binary expression");

            if (binaryExpression is ModulusOperator modulusOperator)
            {
                // This one is special
                if (!TryEmitModulusOperator(modulusOperator))
                {
                    Error(binaryExpression.Right, $"Failed to emit modulus expression: {binaryExpression.Left}");
                    return false;
                }
            }
            else
            {
                if (!TryEmitExpression(binaryExpression.Right, false))
                {
                    Error(binaryExpression.Right, $"Failed to emit right expression: {binaryExpression.Left}");
                    return false;
                }

                if (!TryEmitExpression(binaryExpression.Left, false))
                {
                    Error(binaryExpression.Right, $"Failed to emit left expression: {binaryExpression.Right}");
                    return false;
                }

                switch (binaryExpression)
                {
                    case AdditionOperator _:
                        Emit(Instruction.ADD());
                        break;
                    case SubtractionOperator _:
                        Emit(Instruction.SUB());
                        break;
                    case MultiplicationOperator _:
                        Emit(Instruction.MUL());
                        break;
                    case DivisionOperator _:
                        Emit(Instruction.DIV());
                        break;
                    case LogicalOrOperator _:
                        Emit(Instruction.OR());
                        break;
                    case LogicalAndOperator _:
                        Emit(Instruction.AND());
                        break;
                    case EqualityOperator _:
                        Emit(Instruction.EQ());
                        break;
                    case NonEqualityOperator _:
                        Emit(Instruction.NEQ());
                        break;
                    case LessThanOperator _:
                        Emit(Instruction.S());
                        break;
                    case GreaterThanOperator _:
                        Emit(Instruction.L());
                        break;
                    case LessThanOrEqualOperator _:
                        Emit(Instruction.SE());
                        break;
                    case GreaterThanOrEqualOperator _:
                        Emit(Instruction.LE());
                        break;
                    default:
                        Error(binaryExpression, $"Emitting binary expression '{binaryExpression}' not implemented");
                        return false;
                }
            }
        }

        return true;
    }

    private bool TryEmitModulusOperator(ModulusOperator modulusOperator)
    {
        var value = modulusOperator.Left;
        var number = modulusOperator.Right;

        if (!TryEmitModulus(value, number))
            return false;

        return true;
    }

    private bool TryEmitModulus(Expression value, Expression number)
    {
        // value % number turns into
        // value - ( ( value / number ) * value )

        // push number for multiplication
        if (!TryEmitExpression(number, false))
            return false;

        // value / number
        if (!TryEmitExpression(number, false))
            return false;

        if (!TryEmitExpression(value, false))
            return false;

        Emit(Instruction.DIV());

        // *= number
        Emit(Instruction.MUL());

        // value - ( ( value / number ) * number )
        if (!TryEmitExpression(value, false))
            return false;

        Emit(Instruction.SUB());

        // Result value is on stack
        return true;
    }

    private bool TryEmitPushVariableValue(Identifier identifier)
    {
        Trace(identifier, $"Emitting variable reference: {identifier}");

        if (!Scope.TryGetVariable(identifier.Text, out var variable))
        {
            Error(identifier, $"Referenced undeclared variable '{identifier}'");
            return false;
        }

        if (!TryEmitPushVariableValue(variable.Declaration.Modifier, variable.Declaration.Type.ValueKind, variable.Index,
                                        variable.Declaration.Initializer))
        {
            return false;
        }

        return true;
    }

    private bool TryEmitPushVariableValue(VariableModifier modifier, ValueKind valueKind, short index, Expression initializer)
    {
        if (modifier == null || modifier.Kind == VariableModifierKind.Local)
        {
            if (valueKind != ValueKind.Float)
                Emit(Instruction.PUSHLIX(index));
            else
                Emit(Instruction.PUSHLFX(index));
        }
        else if (modifier.Kind == VariableModifierKind.Global)
        {
            if (valueKind != ValueKind.Float)
                Emit(Instruction.PUSHIX(index));
            else
                Emit(Instruction.PUSHIF(index));
        }
        else if (modifier.Kind == VariableModifierKind.Constant)
        {
            if (!TryEmitExpression(initializer, false))
            {
                Error(initializer, $"Failed to emit value for constant expression: {initializer}");
                return false;
            }
        }
        else if (modifier.Kind == VariableModifierKind.AiLocal)
        {
            Emit(Instruction.PUSHIS(index));
            Emit(Instruction.COMM(mInstrinsic.AiGetLocalFunctionIndex)); // AI_GET_LOCAL_PARAM
            Emit(Instruction.PUSHREG());
        }
        else if (modifier.Kind == VariableModifierKind.AiGlobal)
        {
            Emit(Instruction.PUSHIS(index));
            Emit(Instruction.COMM(mInstrinsic.AiGetGlobalFunctionIndex)); // AI_GET_GLOBAL
            Emit(Instruction.PUSHREG());
        }
        else if (modifier.Kind == VariableModifierKind.Bit)
        {
            Emit(Instruction.PUSHIS(index));
            Emit(Instruction.COMM(mInstrinsic.BitCheckFunctionIndex)); // BIT_CHK
            Emit(Instruction.PUSHREG());
        }
        else if (modifier.Kind == VariableModifierKind.Count)
        {
            Emit(Instruction.PUSHIS(index));
            Emit(Instruction.COMM(mInstrinsic.GetCountFunctionIndex)); // GET_COUNT
            Emit(Instruction.PUSHREG());
        }
        else
        {
            Error(modifier, "Unsupported variable modifier type");
            return false;
        }

        return true;
    }

    private bool TryEmitVariableAssignmentBase(AssignmentOperatorBase assignment, bool isStatement)
    {
        if (assignment is CompoundAssignmentOperator compoundAssignment)
        {
            if (!TryEmitVariableCompoundAssignment(compoundAssignment, isStatement))
            {
                Error(compoundAssignment, $"Failed to emit compound assignment: {compoundAssignment}");
                return false;
            }
        }
        else
        {
            if (assignment.Left is Identifier identifier)
            {
                if (!TryEmitVariableAssignment(identifier, assignment.Right, isStatement))
                {
                    Error(assignment, $"Failed to emit assignment: {assignment}");
                    return false;
                }
            }
            else if (assignment.Left is SubscriptOperator subscriptOperator)
            {
                if (!TryEmitSubscriptAssignment(assignment, isStatement))
                {
                    Error(subscriptOperator, $"Failed to emit subscript: {subscriptOperator}");
                    return false;
                }
            }
            else
            {
                Error(assignment, $"Failed to emit assignment: {assignment}");
                return false;
            }
        }

        return true;
    }

    private bool TryEmitSubscriptAssignment(AssignmentOperatorBase assignmentOperator, bool isStatement)
    {
        var subscriptOperator = assignmentOperator.Left as SubscriptOperator;
        if (!Scope.TryGetVariable(subscriptOperator.Operand.Text, out var variable))
        {
            Error(assignmentOperator, $"Reference to undefined variable '{subscriptOperator.Operand.Text}'");
            return false;
        }

        if (!TryEmitExpression(assignmentOperator.Right, false))
        {
            Error(assignmentOperator, "Invalid expression");
            return false;
        }

        if (subscriptOperator.Index is IntLiteral intLiteral)
        {
            // Known index
            if (!TryEmitVariableAssignment(variable.Declaration, variable.GetArrayElementIndex(intLiteral)))
                return false;
        }
        else
        {
            // Unknown index
            // Start emitting subscript code
            var endLabel = CreateLabel($"SubscriptAssignmentEndLabel");
            for (int i = 0; i < variable.Size; i++)
            {
                var falseLabel = CreateLabel($"SubscriptAssignmentIfNot{i}");

                // Emit current index
                EmitPushIntLiteral(i);

                // Emit index expression
                if (!TryEmitExpression(subscriptOperator.Index, false))
                    return false;

                // Emit equals instruction (index == i)
                Emit(Instruction.EQ());

                // Check if index == i
                Emit(Instruction.IF(falseLabel.Index));
                {
                    // Assign value
                    if (!TryEmitVariableAssignment(variable.Declaration, variable.GetArrayElementIndex(i)))
                        return false;

                    // Jump to the end of the subscript code
                    Emit(Instruction.GOTO(endLabel.Index));
                }

                // Resolve the label for when the condition is not met
                ResolveLabel(falseLabel);
            }

            // Resolve the end of the subscript code label
            ResolveLabel(endLabel);
        }

        if (!isStatement)
            TryEmitExpression(assignmentOperator.Right, false);

        return true;
    }

    private bool TryEmitVariableCompoundAssignment(CompoundAssignmentOperator compoundAssignment, bool isStatement)
    {
        Trace(compoundAssignment, $"Emitting compound assignment: {compoundAssignment}");

        var identifier = compoundAssignment.Left as Identifier;
        if (identifier == null)
        {
            Error(compoundAssignment, $"Expected assignment to variable: {compoundAssignment}");
            return false;
        }

        if (compoundAssignment is ModulusAssignmentOperator _)
        {
            // Special treatment because it doesnt have an instruction
            if (!TryEmitModulus(compoundAssignment.Left, compoundAssignment.Right))
            {
                Error(compoundAssignment, $"Failed to emit modulus assignment operator: {compoundAssignment}");
                return false;
            }
        }
        else
        {
            // Push value of right expression
            if (!TryEmitExpression(compoundAssignment.Right, false))
            {
                Error(compoundAssignment.Right, $"Failed to emit expression: {compoundAssignment.Right}");
                return false;
            }

            // Push value of variable
            if (!TryEmitPushVariableValue(identifier))
            {
                Error(identifier, $"Failed to emit variable value for: {identifier}");
                return false;
            }

            // Emit operation
            switch (compoundAssignment)
            {
                case AdditionAssignmentOperator _:
                    Emit(Instruction.ADD());
                    break;

                case SubtractionAssignmentOperator _:
                    Emit(Instruction.SUB());
                    break;

                case MultiplicationAssignmentOperator _:
                    Emit(Instruction.MUL());
                    break;

                case DivisionAssignmentOperator _:
                    Emit(Instruction.DIV());
                    break;

                default:
                    Error(compoundAssignment, $"Unknown compound assignment type: {compoundAssignment}");
                    return false;
            }
        }

        // Assign the value to the variable
        if (!TryEmitVariableAssignment(identifier))
        {
            Error(identifier, $"Failed to assign value to variable: {identifier}");
            return false;
        }

        if (!isStatement)
        {
            Trace(compoundAssignment, $"Pushing variable value: {identifier}");

            // Push value of variable
            if (!TryEmitPushVariableValue(identifier))
            {
                Error(identifier, $"Failed to emit variable value for: {identifier}");
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
    private bool TryEmitVariableAssignment(Identifier identifier, Expression expression, bool isStatement)
    {
        Trace($"Emitting variable assignment: {identifier} = {expression}");

        if (expression is InitializerList initializerList)
        {
            if (!Scope.TryGetVariable(identifier.Text, out var variable))
                return false;

            if (!variable.Declaration.IsArray)
                return false;

            if (initializerList.Expressions.Count != variable.Size)
            {
                Error(initializerList, "Size of initializer list does not match size of declaration");
                return false;
            }

            // Assign each array element with its value
            for (int i = 0; i < initializerList.Expressions.Count; i++)
            {
                var expr = initializerList.Expressions[i];
                var index = variable.GetArrayElementIndex(i);

                if (!TryEmitExpression(expr, false))
                {
                    Error(expression, "Failed to emit code for assigment value expression");
                    return false;
                }

                if (!TryEmitVariableAssignment(variable.Declaration, index))
                {
                    Error(identifier, "Failed to emit code for value assignment to variable");
                    return false;
                }
            }
        }
        else
        {
            if (!TryEmitExpression(expression, false))
            {
                Error(expression, "Failed to emit code for assigment value expression");
                return false;
            }

            if (!TryEmitVariableAssignment(identifier))
            {
                Error(identifier, "Failed to emit code for value assignment to variable");
                return false;
            }

            if (!isStatement)
            {
                // Push value of variable
                Trace(identifier, $"Pushing variable value: {identifier}");

                if (!TryEmitPushVariableValue(identifier))
                {
                    Error(identifier, $"Failed to emit variable value for: {identifier}");
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Emit variable assignment without explicit expression.
    /// </summary>
    /// <param name="identifier"></param>
    /// <returns></returns>
    private bool TryEmitVariableAssignment(Identifier identifier)
    {
        if (!Scope.TryGetVariable(identifier.Text, out var variable))
        {
            Error(identifier, $"Assignment to undeclared variable: {identifier}");
            return false;
        }

        if (!TryEmitVariableAssignment(variable.Declaration, variable.Index))
            return false;

        return true;
    }

    private bool TryEmitVariableAssignment(VariableDeclaration declaration, short index)
    {
        // load the value into the variable
        if (declaration.Modifier == null || declaration.Modifier.Kind == VariableModifierKind.Local)
        {
            if (declaration.Type.ValueKind != ValueKind.Float)
                Emit(Instruction.POPLIX(index));
            else
                Emit(Instruction.POPLFX(index));
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Global)
        {
            if (declaration.Type.ValueKind != ValueKind.Float)
                Emit(Instruction.POPIX(index));
            else
                Emit(Instruction.POPFX(index));
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Constant)
        {
            Error(declaration.Identifier, "Illegal assignment to constant");
            return false;
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.AiLocal)
        {
            // implicit pop of value
            Emit(Instruction.PUSHIS(index));
            Emit(Instruction.COMM(mInstrinsic.AiSetLocalFunctionIndex)); // AI_SET_LOCAL_PARAM
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.AiGlobal)
        {
            // implicit pop of value
            Emit(Instruction.PUSHIS(index));
            Emit(Instruction.COMM(mInstrinsic.AiSetGlobalFunctionIndex)); // AI_SET_GLOBAL
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Bit)
        {
            var falseLabel = CreateLabel("BitAssignmentIfFalse");
            var endLabel = CreateLabel("BitAssignmentIfEnd");

            // implicit pop of value
            Emit(Instruction.IF(falseLabel.Index));
            {
                // Value assigned is true
                Emit(Instruction.PUSHIS(index));
                Emit(Instruction.COMM(mInstrinsic.BitOnFunctionIndex)); // BIT_ON
                Emit(Instruction.GOTO(endLabel.Index));
            }
            // Else
            {
                // Value assigned is false
                ResolveLabel(falseLabel);
                Emit(Instruction.PUSHIS(index));
                Emit(Instruction.COMM(mInstrinsic.BitOffFunctionIndex)); // BIT_OFF
                Emit(Instruction.GOTO(endLabel.Index));
            }
            ResolveLabel(endLabel);
        }
        else if (declaration.Modifier.Kind == VariableModifierKind.Count)
        {
            // implicit pop of value
            Emit(Instruction.PUSHIS(index));
            Emit(Instruction.COMM(mInstrinsic.SetCountFunctionIndex)); // SET_COUNT
        }
        else
        {
            Error(declaration.Identifier, $"Unsupported variable modifier type: {declaration.Modifier}");
            return false;
        }

        return true;
    }

    //
    // Literal values
    //
    private void EmitPushBoolLiteral(BoolLiteral boolLiteral)
    {
        Trace(boolLiteral, $"Pushing bool literal: {boolLiteral}");

        if (boolLiteral.Value)
            Emit(Instruction.PUSHIS(1));
        else
            Emit(Instruction.PUSHIS(0));
    }

    private void EmitPushIntLiteral(IntLiteral intLiteral)
    {
        Trace(intLiteral, $"Pushing int literal: {intLiteral}");

        // Original scripts never use negative literals
        // so if our literal is negative, we make it positive
        // and later negative it using the negation operator
        var value = intLiteral.Value;
        var isNegative = false;
        if (value < 0)
        {
            isNegative = true;
            value = -value;
        }

        if ((value & ~0x7FFF) == 0)
            Emit(Instruction.PUSHIS((short)value));
        else
            Emit(Instruction.PUSHI(value));

        if (isNegative)
            Emit(Instruction.MINUS());
    }

    private void EmitPushFloatLiteral(FloatLiteral floatLiteral)
    {
        Trace(floatLiteral, $"Pushing float literal: {floatLiteral}");

        // Original scripts never use negative literals
        // so if our literal is negative, we make it positive
        // and later negative it using the negation operator
        var value = floatLiteral.Value;
        var isNegative = false;
        if (value < 0)
        {
            isNegative = true;
            value = -value;
        }

        Emit(Instruction.PUSHF(value));
        if (isNegative)
            Emit(Instruction.MINUS());
    }

    private void EmitPushStringLiteral(StringLiteral stringLiteral)
    {
        Trace(stringLiteral, $"Pushing string literal: {stringLiteral}");

        Emit(Instruction.PUSHSTR(stringLiteral.Value));
    }

    private bool IntFitsInShort(int value)
    {
        return (((value & 0xffff8000) + 0x8000) & 0xffff7fff) == 0;
    }

    // 
    // If statement
    //
    private bool TryEmitIfStatement(IfStatement ifStatement)
    {
        Trace(ifStatement, $"Emitting if statement: '{ifStatement}'");

        // emit condition expression, which should push a boolean value to the stack
        if (!TryEmitExpression(ifStatement.Condition, false))
        {
            Error(ifStatement.Condition, "Failed to emit if statement condition");
            return false;
        }

        // create else label
        LabelInfo elseLabel = null;
        if (ifStatement.ElseBody != null)
            elseLabel = CreateLabel("IfElseLabel");

        // generate label for jump if condition is false
        var endLabel = CreateLabel("IfEndLabel");

        // emit if instruction that jumps to the label if the condition is false
        if (ifStatement.ElseBody == null)
        {
            Emit(Instruction.IF(endLabel.Index));
        }
        else
        {
            Emit(Instruction.IF(elseLabel.Index));
        }

        // compile if body
        if (ifStatement.ElseBody == null && !Matching)
        {
            // If there's no else, then the end of the body will line up with the end label
            if (!TryEmitIfStatementBody(ifStatement.Body, null))
                return false;
        }
        else
        {
            // If there's an else body, then the end of the body will line up with the else label, but it should line up with the end label
            if (!TryEmitIfStatementBody(ifStatement.Body, endLabel))
                return false;
        }

        if (ifStatement.ElseBody != null)
        {
            ResolveLabel(elseLabel);

            // compile if else body
            // The else body will always line up with the end label
            if (!TryEmitIfStatementBody(ifStatement.ElseBody, Matching ? endLabel : null))
                return false;
        }

        ResolveLabel(endLabel);

        return true;
    }

    private bool TryEmitIfStatementBody(CompoundStatement body, LabelInfo endLabel)
    {
        Trace(body, "Compiling if statement body");
        if (!TryEmitCompoundStatement(body))
        {
            Error(body, "Failed to compile if statement body");
            return false;
        }

        // ensure that we end up at the right position after the body
        if (endLabel != null)
            Emit(Instruction.GOTO(endLabel.Index));

        return true;
    }

    // 
    // If statement
    //
    private bool TryEmitForStatement(ForStatement forStatement)
    {
        Trace(forStatement, $"Emitting for statement: '{forStatement}'");

        // Enter for scope
        PushScope();

        // Emit initializer
        if (!TryEmitStatement(forStatement.Initializer))
        {
            Error(forStatement.Condition, "Failed to emit for statement initializer");
            return false;
        }

        // Create labels
        var conditionLabel = CreateLabel("ForConditionLabel");
        var afterLoopLabel = CreateLabel("ForAfterLoopLabel");
        var endLabel = CreateLabel("ForEndLabel");

        // Emit condition check
        {
            ResolveLabel(conditionLabel);

            // Emit condition
            if (!TryEmitExpression(forStatement.Condition, false))
            {
                Error(forStatement.Condition, "Failed to emit for statement condition");
                return false;
            }

            // Jump to the end of the loop if condition is NOT true
            Emit(Instruction.IF(endLabel.Index));
        }

        // Emit body
        {
            // Allow break & continue
            Scope.BreakLabel = endLabel;
            Scope.ContinueLabel = afterLoopLabel;

            // emit body
            Trace(forStatement.Body, "Emitting for statement body");
            if (!TryEmitCompoundStatement(forStatement.Body))
            {
                Error(forStatement.Body, "Failed to emit for statement body");
                return false;
            }
        }

        // Emit after loop
        {
            ResolveLabel(afterLoopLabel);

            if (!TryEmitExpression(forStatement.AfterLoop, true))
            {
                Error(forStatement.AfterLoop, "Failed to emit for statement after loop expression");
                return false;
            }

            // jump to condition check
            Emit(Instruction.GOTO(conditionLabel.Index));
        }

        // We're at the end of the for loop
        ResolveLabel(endLabel);

        // Exit for scope
        PopScope();

        return true;
    }

    // 
    // While statement
    //
    private bool TryEmitWhileStatement(WhileStatement whileStatement)
    {
        Trace(whileStatement, $"Emitting while statement: '{whileStatement}'");

        // Create labels
        var conditionLabel = CreateLabel("WhileConditionLabel");
        var endLabel = CreateLabel("WhileEndLabel");

        // Emit condition check
        {
            ResolveLabel(conditionLabel);

            // compile condition expression, which should push a boolean value to the stack
            if (!TryEmitExpression(whileStatement.Condition, false))
            {
                Error(whileStatement.Condition, "Failed to emit while statement condition");
                return false;
            }

            // Jump to the end of the loop if condition is NOT true
            Emit(Instruction.IF(endLabel.Index));
        }

        // Emit body
        {
            // Enter while body scope
            PushScope();

            // allow break & continue
            Scope.BreakLabel = endLabel;
            Scope.ContinueLabel = conditionLabel;

            // emit body
            Trace(whileStatement.Body, "Emitting while statement body");
            if (!TryEmitCompoundStatement(whileStatement.Body))
            {
                Error(whileStatement.Body, "Failed to emit while statement body");
                return false;
            }

            // jump to condition check
            Emit(Instruction.GOTO(conditionLabel.Index));

            // Exit while body scope
            PopScope();
        }

        // We're at the end of the while loop
        ResolveLabel(endLabel);

        return true;
    }

    //
    // Switch statement
    //
    private bool TryEmitSwitchStatement(SwitchStatement switchStatement)
    {
        Trace(switchStatement, $"Emitting switch statement: '{switchStatement}'");
        PushScope();

        var defaultLabel = switchStatement.Labels.SingleOrDefault(x => x is DefaultSwitchLabel);
        if (switchStatement.Labels.Last() != defaultLabel)
        {
            switchStatement.Labels.Remove(defaultLabel);
            switchStatement.Labels.Add(defaultLabel);
        }

        // Set up switch labels in the context for gotos
        Scope.SwitchLabels = switchStatement.Labels
                                            .Where(x => x is ConditionSwitchLabel)
                                            .Select(x => ((ConditionSwitchLabel)x).Condition)
                                            .ToDictionary(x => x, y => CreateLabel("SwitchConditionCaseBody"));

        var conditionCaseBodyLabels = Scope.SwitchLabels.Values.ToList();

        var defaultCaseBodyLabel = defaultLabel != null ? CreateLabel("SwitchDefaultCaseBody") : null;
        Scope.SwitchLabels.Add(new NullExpression(), defaultCaseBodyLabel);

        var switchEndLabel = CreateLabel("SwitchStatementEndLabel");
        for (var i = 0; i < switchStatement.Labels.Count; i++)
        {
            var label = switchStatement.Labels[i];
            if (label is ConditionSwitchLabel conditionLabel)
            {
                // Emit condition expression, which should push a boolean value to the stack
                if (!TryEmitExpression(conditionLabel.Condition, false))
                {
                    Error(conditionLabel.Condition, "Failed to emit switch statement label condition");
                    return false;
                }

                // emit switch on expression
                if (!TryEmitExpression(switchStatement.SwitchOn, false))
                {
                    Error(switchStatement.SwitchOn, "Failed to emit switch statement condition");
                    return false;
                }

                // emit equality check, but check if it's not equal to jump to the body if it is
                Emit(Instruction.NEQ());

                // generate label for jump if condition is false
                var labelBodyLabel = conditionCaseBodyLabels[i];

                // emit if instruction that jumps to the body if the condition is met
                Emit(Instruction.IF(labelBodyLabel.Index));
            }
        }

        if (defaultLabel != null)
        {
            // Emit body of default case first
            Scope.BreakLabel = switchEndLabel;

            // Resolve label that jumps to the default case body
            ResolveLabel(defaultCaseBodyLabel);

            // Emit default case body
            Trace("Compiling switch statement label body");
            if (!TryEmitStatements(defaultLabel.Body))
            {
                Error("Failed to compile switch statement label body");
                return false;
            }
        }

        // Emit other label bodies
        for (var i = 0; i < switchStatement.Labels.Count; i++)
        {
            var label = switchStatement.Labels[i];

            if (label is ConditionSwitchLabel)
            {
                // Resolve body label
                var labelBodyLabel = conditionCaseBodyLabels[i];
                ResolveLabel(labelBodyLabel);

                // Break jumps to end of switch
                Scope.BreakLabel = switchEndLabel;

                // Emit body
                Trace("Compiling switch statement label body");
                if (!TryEmitStatements(label.Body))
                {
                    Error("Failed to compile switch statement label body");
                    return false;
                }
            }
        }

        ResolveLabel(switchEndLabel);

        PopScope();
        return true;
    }

    //
    // Control statements
    //
    private bool TryEmitBreakStatement(BreakStatement breakStatement)
    {
        if (!Scope.TryGetBreakLabel(out var label))
        {
            Error(breakStatement, "Break statement is invalid in this context");
            return false;
        }

        Emit(Instruction.GOTO(label.Index));

        return true;
    }

    private bool TryEmitContinueStatement(ContinueStatement continueStatement)
    {
        if (!Scope.TryGetContinueLabel(out var label))
        {
            Error(continueStatement, "Continue statement is invalid in this context");
            return false;
        }

        Emit(Instruction.GOTO(label.Index));

        return true;
    }

    private bool TryEmitReturnStatement(ReturnStatement returnStatement)
    {
        Trace(returnStatement, $"Emitting return statement: '{returnStatement}'");

        if (EnableStackCookie)
        {
            // Check stack cookie
            Emit(Instruction.PUSHI(mProcedureDeclaration.Identifier.Text.GetHashCode()));
            Emit(Instruction.NEQ());
            var label = CreateLabel("IfStackCookieIsValid");
            Emit(Instruction.IF(label.Index));
            EmitTracePrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", false);
            EmitTracePrint("!!! Error: Stack cookie is invalid !!!!", false);
            EmitTracePrint("!!! This is likely a compiler bug! !!!!", false);
            EmitTracePrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", false);
            ResolveLabel(label);
        }

        if (EnableProcedureTracing)
        {
            TraceProcedureReturn();
        }

        // Save return address in a temporary variable
        if (returnStatement.Value != null)
        {
            if (mProcedureDeclaration.ReturnType.ValueKind == ValueKind.Void)
            {
                Error(returnStatement, "Procedure with void return type can't return a value");
                return false;
            }

            // Emit return value
            if (!TryEmitExpression(returnStatement.Value, false))
            {
                Error(returnStatement.Value, $"Failed to emit return value: {returnStatement.Value}");
                return false;
            }

            if (mProcedureDeclaration.ReturnType.ValueKind.GetBaseKind() == ValueKind.Int)
                Emit(Instruction.POPLIX(mIntReturnValueVariable.Index));
            else
                Emit(Instruction.POPLFX(mFloatReturnValueVariable.Index));
        }
        else if (mProcedureDeclaration.ReturnType.ValueKind != ValueKind.Void)
        {
            Error(returnStatement, "Missing return statement value for procedure with non-void return type");
            return false;
        }

        // emit end
        Emit(Instruction.END());
        return true;
    }

    private bool TryEmitGotoStatement(GotoStatement gotoStatement)
    {
        Trace(gotoStatement, $"Emitting goto statement: '{gotoStatement}'");

        LabelInfo label = null;

        switch (gotoStatement.Label)
        {
            case Identifier identifier:
                if (!mLabels.TryGetValue(identifier.Text, out label))
                {
                    if (!Scope.TryGetLabel(identifier, out label))
                    {
                        Error(gotoStatement.Label, $"Goto statement referenced undeclared label: {identifier}");
                        return false;
                    }
                }
                break;

            case Expression expression:
                if (!Scope.TryGetLabel(expression, out label))
                {
                    Error(gotoStatement.Label, $"Goto statement referenced undeclared label: {expression}");
                    return false;
                }
                break;
        }

        // emit goto
        Emit(Instruction.GOTO(label.Index));
        return true;
    }

    //
    // Helpers
    //
    private void TraceFunctionCall(FunctionDeclaration declaration)
    {
        EmitTracePrint($"Call to function '{declaration.Identifier}'");
        if (false && declaration.Parameters.Count > 0)
        {
            EmitTracePrint("Arguments:");
            var saves = new Stack<VariableInfo>();

            foreach (var parameter in declaration.Parameters)
            {
                switch (parameter.Type.ValueKind)
                {
                    case ValueKind.Int:
                        saves.Push(EmitTracePrintIntegerNoPush());
                        break;
                    case ValueKind.Float:
                        saves.Push(EmitTracePrintFloatNoPush());
                        break;
                    case ValueKind.Bool:
                        saves.Push(EmitTracePrintBoolNoPush());
                        break;
                    case ValueKind.String:
                        //saves.Push( EmitTracePrintStringNoPush() );
                        break;
                }
            }

            // Push values back onto stack
            while (saves.Count > 0)
            {
                var variable = saves.Pop();
                switch (variable.Declaration.Type.ValueKind)
                {
                    case ValueKind.Bool:
                        EmitUnchecked(Instruction.PUSHLIX(variable.Index));
                        break;
                    case ValueKind.Int:
                        EmitUnchecked(Instruction.PUSHLIX(variable.Index));
                        break;
                    case ValueKind.Float:
                        EmitUnchecked(Instruction.PUSHLFX(variable.Index));
                        break;
                }
            }
        }
    }

    private VariableInfo EmitTracePrintStringNoPush()
    {
        var save = Scope.GenerateVariable(ValueKind.String, mNextIntVariableIndex++);

        // Pop integer value off stack and save it in a temporary variable
        EmitUnchecked(Instruction.POPLFX(save.Index));

        // Print it to log
        EmitUnchecked(Instruction.PUSHLFX(save.Index));
        EmitUnchecked(Instruction.COMM(mInstrinsic.PrintStringFunctionIndex));

        return save;
    }

    private void TraceFunctionCallReturnValue(FunctionDeclaration declaration)
    {
        EmitTracePrint($"Call to function '{declaration.Identifier}' returned:");

        // push return value of function
        Emit(Instruction.PUSHREG());

        EmitTracePrintValue(declaration.ReturnType.ValueKind);
    }

    private void TraceProcedureCall(ProcedureDeclaration declaration)
    {
        EmitTracePrint($"Call to procedure '{declaration.Identifier}'");

        if (false && declaration.Parameters.Count > 0)
        {
            EmitTracePrint("Arguments:");

            int intParameterCount = 1;
            int floatParameterCount = 1;

            foreach (var parameter in declaration.Parameters)
            {
                if (parameter.Type.ValueKind == ValueKind.Int)
                {
                    Emit(Instruction.PUSHLIX((short)(mNextIntArgumentVariableIndex + intParameterCount)));
                }
                if (parameter.Type.ValueKind == ValueKind.Bool)
                {
                    Emit(Instruction.PUSHLIX((short)(mNextIntArgumentVariableIndex + intParameterCount)));
                }
                Emit(Instruction.PUSHLFX((short)(mNextFloatArgumentVariableIndex + floatParameterCount)));

                EmitTracePrintValue(parameter.Type.ValueKind);

                if (parameter.Type.ValueKind == ValueKind.Int)
                {
                    Emit(Instruction.POPLIX((short)(mNextIntArgumentVariableIndex + intParameterCount)));
                    ++intParameterCount;
                }
                if (parameter.Type.ValueKind == ValueKind.Bool)
                {
                    Emit(Instruction.POPLIX((short)(mNextIntArgumentVariableIndex + intParameterCount)));
                    ++intParameterCount;
                }
                Emit(Instruction.POPLFX((short)(mNextFloatArgumentVariableIndex + floatParameterCount)));
                ++floatParameterCount;
            }
        }
    }

    private void TraceProcedureCallReturnValue(ProcedureDeclaration declaration)
    {
        EmitTracePrint($"Call to procedure '{declaration.Identifier}' returned:");

        // Push return value of procedure
        if (declaration.ReturnType.ValueKind.GetBaseKind() == ValueKind.Int)
            Emit(Instruction.PUSHLIX(mIntReturnValueVariable.Index));
        else
            Emit(Instruction.PUSHLFX(mFloatReturnValueVariable.Index));

        EmitTracePrintValue(declaration.ReturnType.ValueKind);
    }

    private void TraceProcedureStart()
    {
        EmitTracePrint($"Entered procedure: '{mProcedureDeclaration.Identifier.Text}'");
    }

    private void TraceProcedureReturn()
    {
        EmitTracePrint($"Exiting procedure: '{mProcedureDeclaration.Identifier.Text}'");
    }

    private void Emit(Instruction instruction)
    {
        // Emit instruction
        mInstructions.Add(instruction);
        TraceInstructionStackBehaviour(instruction);
    }

    private void TraceInstructionStackBehaviour(Instruction instruction)
    {
        switch (instruction.Opcode)
        {
            case Opcode.PUSHI:
            case Opcode.PUSHF:
            case Opcode.PUSHIX:
            case Opcode.PUSHIF:
                ++mStackValueCount;
                break;
            case Opcode.PUSHREG:
                ++mStackValueCount;
                break;
            case Opcode.POPIX:
            case Opcode.POPFX:
                --mStackValueCount;
                break;
            case Opcode.END:
                {
                    // Log stack value count at procedure end
                    mLogger.Debug($"{mStackValueCount} values on stack at END");

                    if (mStackValueCount < 1)
                    {
                        mLogger.Error("Stack underflow!!!");
                    }
                    else if (mStackValueCount != 1)
                    {
                        mLogger.Error("Return address corruption");
                    }
                }
                break;
            case Opcode.ADD:
            case Opcode.SUB:
            case Opcode.MUL:
            case Opcode.DIV:
                mStackValueCount -= 2;
                ++mStackValueCount;
                break;
            case Opcode.EQ:
            case Opcode.NEQ:
            case Opcode.S:
            case Opcode.L:
            case Opcode.SE:
            case Opcode.LE:
            case Opcode.IF:
                mStackValueCount -= 2;
                ++mStackValueCount;
                break;
            case Opcode.PUSHIS:
            case Opcode.PUSHLIX:
            case Opcode.PUSHLFX:
                ++mStackValueCount;
                break;
            case Opcode.POPLIX:
            case Opcode.POPLFX:
                --mStackValueCount;
                break;
            case Opcode.PUSHSTR:
                ++mStackValueCount;
                break;
            case Opcode.CALL:
                break;
            case Opcode.COMM:
                {
                    var functionCalled = mRootScope.Functions.Values.First(x => x.Index == instruction.Operand.Int16Value);
                    mStackValueCount -= functionCalled.Declaration.Parameters.Count;
                }
                break;
            case Opcode.OR:
                mStackValueCount -= 2;
                ++mStackValueCount;
                break;
            case Opcode.PROC:
                break;
            case Opcode.JUMP:
                break;
            case Opcode.RUN:
                break;
            case Opcode.GOTO:
                break;
            case Opcode.MINUS:
                --mStackValueCount;
                ++mStackValueCount;
                break;
            case Opcode.NOT:
                --mStackValueCount;
                ++mStackValueCount;
                break;
            case Opcode.AND:
                mStackValueCount -= 2;
                ++mStackValueCount;
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private void EmitTracePrint(string message, bool prefixTrace = true)
    {
        var messageFormatted = message;
        if (prefixTrace)
            messageFormatted = $"Trace: {message}";

        EmitUnchecked(Instruction.PUSHSTR(messageFormatted));
        EmitUnchecked(Instruction.COMM(mInstrinsic.PrintStringFunctionIndex));
    }

    private void EmitTracePrintValue(ValueKind kind)
    {
        switch (kind)
        {
            case ValueKind.Int:
                EmitTracePrintInteger();
                break;
            case ValueKind.Float:
                EmitTracePrintFloat();
                break;
            case ValueKind.Bool:
                EmitTracePrintBool();
                break;
        }
    }

    private void EmitTracePrintInteger()
    {
        var save = EmitTracePrintIntegerNoPush();

        // Push the value back to the stack
        EmitUnchecked(Instruction.PUSHLIX(save.Index));
    }

    private VariableInfo EmitTracePrintIntegerNoPush()
    {
        var save = Scope.GenerateVariable(ValueKind.Int, mNextIntVariableIndex++);

        // Pop integer value off stack and save it in a temporary variable
        EmitUnchecked(Instruction.POPLIX(save.Index));

        // Print it to log
        EmitUnchecked(Instruction.PUSHLIX(save.Index));
        EmitUnchecked(Instruction.COMM(mInstrinsic.PrintIntFunctionIndex));

        return save;
    }

    private void EmitTracePrintFloat()
    {
        var save = EmitTracePrintFloatNoPush();

        // Push the value back to the stack
        EmitUnchecked(Instruction.PUSHLFX(save.Index));
    }

    private VariableInfo EmitTracePrintFloatNoPush()
    {
        var save = Scope.GenerateVariable(ValueKind.Float, mNextFloatVariableIndex++);

        // Pop integer value off stack and save it in a temporary variable
        EmitUnchecked(Instruction.POPLFX(save.Index));

        // Print it to log
        EmitUnchecked(Instruction.PUSHLFX(save.Index));
        EmitUnchecked(Instruction.COMM(mInstrinsic.PrintFloatFunctionIndex));

        return save;
    }

    private void EmitTracePrintBool()
    {
        var save = EmitTracePrintBoolNoPush();

        // Push the value back to the stack
        EmitUnchecked(Instruction.PUSHLIX(save.Index));
    }

    private VariableInfo EmitTracePrintBoolNoPush()
    {
        var save = Scope.GenerateVariable(ValueKind.Int, mNextIntVariableIndex++);

        // Pop integer value off stack and save it in a temporary variable
        EmitUnchecked(Instruction.POPLIX(save.Index));

        // Print it to log
        var elseLabel = CreateLabel("IfElseLabel");
        var endLabel = CreateLabel("IfEndLabel");

        // if ( x == 1 )
        EmitUnchecked(Instruction.PUSHIS(1));
        EmitUnchecked(Instruction.PUSHLIX(save.Index));
        EmitUnchecked(Instruction.EQ());
        EmitUnchecked(Instruction.IF(elseLabel.Index));
        {
            // PUTS( "true" );
            EmitTracePrint("true");
            EmitUnchecked(Instruction.GOTO(endLabel.Index));
        }
        // else
        ResolveLabel(elseLabel);
        {
            // PUTS( "false" );
            EmitTracePrint("false");
        }
        ResolveLabel(endLabel);

        return save;
    }

    private void EmitUnchecked(Instruction instruction)
    {
        mInstructions.Add(instruction);
    }

    private LabelInfo CreateLabel(string name)
    {
        var label = new LabelInfo();
        label.Index = (short)mLabels.Count;
        label.Name = name + "_" + mNextLabelIndex++;

        mLabels.Add(label.Name, label);

        return label;
    }

    private void ResolveLabel(LabelInfo label)
    {
        label.InstructionIndex = (short)(mInstructions.Count);
        label.IsResolved = true;

        Trace($"Resolved label {label.Name} to instruction index {label.InstructionIndex}");
    }

    private void PushScope()
    {
        mScopeStack.Push(new ScopeContext(mScopeStack.Peek()));
        Trace("Entered scope");
    }

    private void PopScope()
    {
        //mNextIntVariableIndex -= ( short )Scope.Variables.Count( x => sTypeToBaseTypeMap[x.Value.Declaration.Type.ValueType] == FlowScriptValueType.Int );
        //mNextFloatVariableIndex -= ( short )Scope.Variables.Count( x => sTypeToBaseTypeMap[x.Value.Declaration.Type.ValueType] == FlowScriptValueType.Float );
        mScopeStack.Pop();
        Trace("Exited scope");
    }

    //
    // Logging
    //
    private void Trace(SyntaxNode node, string message)
    {
        if (node.SourceInfo != null)
            Trace($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
        else
            Trace(message);
    }

    private void Trace(string message)
    {
        mLogger.Trace($"{message}");
    }

    private void Info(SyntaxNode node, string message)
    {
        if (node.SourceInfo != null)
            Info($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
        else
            Info(message);
    }

    private void Info(string message)
    {
        mLogger.Info($"{message}");
    }

    private void Error(SyntaxNode node, string message)
    {
        if (node.SourceInfo != null)
            Error($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
        else
            Error(message);

        //if ( Debugger.IsAttached )
        //    Debugger.Break();
    }

    private void Error(string message)
    {
        mLogger.Error($"{message}");

        //if ( Debugger.IsAttached )
        //    Debugger.Break();
    }

    private void Warning(SyntaxNode node, string message)
    {
        if (node.SourceInfo != null)
            Warning($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
        else
            Warning(message);
    }

    private void Warning(string message)
    {
        mLogger.Warning($"{message}");
    }
}
