using Antlr4.Runtime;
using Antlr4.Runtime.Tree;
using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.Common.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using MessageScriptParser = AtlusScriptLibrary.MessageScriptLanguage.Compiler.Parser.MessageScriptParser;
using MessageScriptParserHelper = AtlusScriptLibrary.MessageScriptLanguage.Compiler.Parser.MessageScriptParserHelper;

namespace AtlusScriptLibrary.MessageScriptLanguage.Compiler;

// Todo: improve error logging in general
// Todo: add exception settings?

/// <summary>
/// Represents the compiler that compiles MessageScript text sources to their appropriate binary equivalents.
/// </summary>
public class MessageScriptCompiler
{
    private readonly Logger mLogger;
    private readonly FormatVersion mVersion;
    private readonly HashSet<int> mImportedFileHashSet;
    private readonly Encoding mEncoding;
    private readonly Dictionary<string, int> mVariables;
    private string mFilePath;
    private MessageScript mScript;
    private List<MessageScript> mImports;

    public Library Library { get; set; }

    /// <summary>
    /// If true when there are message name conflicts an existing message of the same name will be overwritten. 
    /// Otherwise an error will occur and the existing message will not be changed
    /// </summary>
    public bool OverwriteExistingMsgs { get; set; } = false;

    /// <summary>
    /// Constructs a new instance of <see cref="MessageScriptCompiler"/> which will compile to the specified format.
    /// </summary>
    /// <param name="version">The version of the format to compile the output to.</param>
    /// <param name="encoding">The encoding to use for non-ASCII characters. If not specified, non-ASCII characters will be ignored unless they are stored as [x XX YY] tags.</param>
    public MessageScriptCompiler(FormatVersion version, Encoding encoding = null)
    {
        mVersion = version;
        mEncoding = encoding;
        mLogger = new Logger(nameof(MessageScriptCompiler));
        mVariables = new Dictionary<string, int>();
        mImports = new List<MessageScript>();
        mImportedFileHashSet = new HashSet<int>();

        LoggerManager.RegisterLogger(mLogger);
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
    /// Tries to compile the provided MessageScript source with given imports. Returns a boolean indicating if the operation succeeded.
    /// </summary>
    /// <param name="baseBmdStream">A FileStream of the base bmd file</param>
    /// <param name="imports">A List of paths to .msg files that will be forcibly imported</param>
    /// <param name="messageScript">The compiled MessageScript</param>
    /// <returns>True if the file successfully compiled, false otherwise</returns>
    public bool TryCompileWithImports(FileStream baseBmdStream, List<string> imports, out MessageScript messageScript)
    {
        // Parse base bmd
        if (baseBmdStream != null)
            mScript = MessageScript.FromStream(baseBmdStream, mVersion, mEncoding, false);

        if(imports.Count > 0)
        {
            mFilePath = Path.GetFullPath(imports[0]);
        }

        if(!TryResolveImports(imports))
        {
            messageScript = null;
            return false;
        }

        for (int i = 0; i < mScript.Dialogs.Count; i++)
        {
            var dialog = mScript.Dialogs[i];

            if (OverwriteExistingMsgs)
            {
                // Try and replace the current one with the last one
                int last = mScript.Dialogs.FindLastIndex(msg => msg.Name == dialog.Name);
                mScript.Dialogs[i] = mScript.Dialogs[last]; // Replace current one
                dialog = mScript.Dialogs[i];
                while (last != i) // Keep removing from the end until there's only one
                {
                    mScript.Dialogs.RemoveAt(last);
                    last = mScript.Dialogs.FindLastIndex(msg => msg.Name == dialog.Name);
                }
            }
        }
        messageScript = mScript; //TODO: maybe this should be checked again...
        return true;
    }

    private bool TryResolveImports(List<string> imports)
    {
        LogInfo("Resolving imports");

        foreach (var import in imports)
        {
            if (!TryResolveMessageScriptImport(import, out var messageScript))
            {
                LogError($"Failed to resolve MessageScript import: {import}");
                return false;
            }

            // Will be null if it was already imported before
            if (messageScript != null)
                mImports.Add(messageScript);
        }

        // Resolve MessageScripts imports
        if (mImports.Count > 0)
            MergeMessageScripts(mImports);

        LogInfo("Done resolving imports");

        return true;
    }

    private bool TryResolveMessageScriptImport(string import, out MessageScript messageScript)
    {
        LogInfo($"Resolving MessageScript import '{import}'");

        if (!TryGetFullImportPath(import, out var compilationUnitFilePath))
        {
            messageScript = null;
            return false;
        }

        LogInfo($"Importing MessageScript from file '{compilationUnitFilePath}'");

        string messageScriptSource;

        try
        {
            messageScriptSource = File.ReadAllText(compilationUnitFilePath);
        }
        catch (Exception)
        {
            LogError($"Can't open MessageScript file to import: {import}");
            messageScript = null;
            return false;
        }

        int messageScriptSourceHash = messageScriptSource.GetHashCode();

        if (!mImportedFileHashSet.Contains(messageScriptSourceHash))
        {
            if (!TryCompile(messageScriptSource, out messageScript))
            {
                LogError($"Import MessageScript failed to compile: {import}");
                return false;
            }

            mImportedFileHashSet.Add(messageScriptSourceHash);
        }
        else
        {
            LogWarning($"MessageScript file '{compilationUnitFilePath}' was already included once! Skipping!");
            messageScript = null;
        }

        return true;
    }

    private bool TryGetFullImportPath(string import, out string path)
    {
        var compilationUnitFilePath = import;

        if (!File.Exists(compilationUnitFilePath))
        {
            // Retry as relative path if we have a filename
            if (mFilePath != null)
            {
                compilationUnitFilePath = Path.Combine(Path.GetDirectoryName(mFilePath), compilationUnitFilePath);

                if (!File.Exists(compilationUnitFilePath))
                {
                    LogError($"File to import does not exist: {import}");
                    path = null;
                    return false;
                }
            }
            else
            {
                LogError($"File to import does not exist: {import}");
                path = null;
                return false;
            }
        }

        path = compilationUnitFilePath;
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

        if (mScript == null)
            mScript = messageScript;
        else
            mScript.Dialogs.AddRange(messageScript.Dialogs);
    }

    /// <summary>
    /// Compile the given input source. An exception is thrown on failure.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <returns>The output of the compilation.</returns>
    public MessageScript Compile(string input)
    {
        if (!TryCompile(input, out var script))
            throw new MessageScriptCompilationFailureException();

        return script;
    }

    /// <summary>
    /// Compile the given input source. An exception is thrown on failure.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <returns>The output of the compilation.</returns>
    public MessageScript Compile(TextReader input)
    {
        if (!TryCompile(input, out var script))
            throw new MessageScriptCompilationFailureException();

        return script;
    }

    /// <summary>
    /// Compile the given input source. An exception is thrown on failure.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <returns>The output of the compilation.</returns>
    public MessageScript Compile(Stream input)
    {
        if (!TryCompile(input, out var script))
            throw new MessageScriptCompilationFailureException();

        return script;
    }

    /// <summary>
    /// Attempts to compile the given input source.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <param name="script">The output of the compilaton. Is only guaranteed to be valid if the operation succeeded.</param>
    /// <returns>A boolean value indicating whether the compilation succeeded or not.</returns>
    public bool TryCompile(string input, out MessageScript script)
    {
        LogInfo("Parsing MessageScript source");
        var cst = MessageScriptParserHelper.ParseCompilationUnit(input, new AntlrErrorListener(this));
        LogInfo("Done parsing MessageScript source");

        return TryCompile(cst, out script);
    }

    /// <summary>
    /// Attempts to compile the given input source.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <param name="script">The output of the compilaton. Is only guaranteed to be valid if the operation succeeded.</param>
    /// <returns>A boolean value indicating whether the compilation succeeded or not.</returns>
    public bool TryCompile(TextReader input, out MessageScript script)
    {
        LogInfo("Parsing MessageScript source");
        var cst = MessageScriptParserHelper.ParseCompilationUnit(input, new AntlrErrorListener(this));
        LogInfo("Done parsing MessageScript source");

        return TryCompile(cst, out script);
    }

    /// <summary>
    /// Attempts to compile the given input source.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <param name="script">The output of the compilaton. Is only guaranteed to be valid if the operation succeeded.</param>
    /// <returns>A boolean value indicating whether the compilation succeeded or not.</returns>
    public bool TryCompile(Stream input, out MessageScript script)
    {
        LogInfo("Parsing MessageScript source");
        var cst = MessageScriptParserHelper.ParseCompilationUnit(input, new AntlrErrorListener(this));
        LogInfo("Done parsing MessageScript source");

        return TryCompile(cst, out script);
    }

    // Compilation methods
    private bool TryCompile(MessageScriptParser.CompilationUnitContext context, out MessageScript script)
    {
        LogInfo(context, "Compiling MessageScript compilation unit");

        if (!TryCompileImpl(context, out script))
        {
            LogError(context, "Failed to compile message script");
            return false;
        }

        LogInfo(context, "Done compiling MessageScript compilation unit");

        return true;
    }

    private bool TryCompileImpl(MessageScriptParser.CompilationUnitContext context, out MessageScript script)
    {
        LogContextInfo(context);

        script = null;

        if (!TryGetFatal(context, context.dialog, "Expected message dialog window", out var dialogContexts))
        {
            return false;
        }

        script = new MessageScript(mVersion, mEncoding);

        foreach (var dialogContext in dialogContexts)
        {
            IDialog dialog;

            if (TryGet(dialogContext, () => dialogContext.messageDialog(), out var messageDialogContext))
            {
                if (!TryCompileMessageDialog(messageDialogContext, out var dialogWindow))
                {
                    LogError(messageDialogContext, "Failed to compile dialog window");
                    return false;
                }

                dialog = dialogWindow;
            }
            else if (TryGet(dialogContext, () => dialogContext.selectionDialog(), out var selectionDialogContext))
            {
                if (!TryCompileSelectionDialog(selectionDialogContext, out var selectionWindow))
                {
                    LogError(selectionDialogContext, "Failed to compile selection window");
                    return false;
                }

                dialog = selectionWindow;
            }
            else
            {
                LogError(dialogContext, "Expected dialog or selection window");
                return false;
            }

            // Declare variable for dialog name referring to index
            mVariables[dialog.Name] = script.Dialogs.Count;
            script.Dialogs.Add(dialog);
        }

        return true;
    }

    private bool TryCompileMessageDialog(MessageScriptParser.MessageDialogContext context, out MessageDialog messageDialog)
    {
        LogContextInfo(context);

        messageDialog = null;

        //
        // Parse identifier
        //
        string identifier;
        {
            if (!TryGetFatal(context, context.Identifier, "Expected dialog window name", out var identifierNode))
                return false;

            identifier = ParseIdentifier(identifierNode);
        }

        LogInfo(context, $"Compiling dialog window: {identifier}");

        //
        // Parse speaker name
        //
        ISpeaker speaker = null;
        if (TryGet(context, context.speakerName, out var speakerNameContentContext))
        {
            if (!TryGetFatal(speakerNameContentContext, () => speakerNameContentContext.tokenText(), "Expected dialog window speaker name text", out var speakerNameTagTextContext))
                return false;

            if (speakerNameTagTextContext.ChildCount != 0)
            {
                if (!TryCompileTokenText(speakerNameTagTextContext, out var speakerNameLines))
                {
                    LogError(speakerNameContentContext, "Failed to compile dialog window speaker name");
                    return false;
                }

                if (speakerNameLines.Count != 0 && speakerNameLines[0].Tokens.Count != 0)
                {
                    if (speakerNameLines.Count > 1)
                        LogWarning(speakerNameTagTextContext, "More than 1 line for dialog window speaker name. Only the 1st line will be used");

                    if (speakerNameLines[0].Tokens[0].Kind == TokenKind.String)
                    {
                        // This is kind of a hack
                        var text = ((StringToken)speakerNameLines[0].Tokens[0]).Value;
                        if (int.TryParse(text, out int variableIndex))
                        {
                            speaker = new VariableSpeaker(variableIndex);
                        }
                        else
                        {
                            speaker = new NamedSpeaker(speakerNameLines[0]);
                        }
                    }
                    else
                    {
                        speaker = new NamedSpeaker(speakerNameLines[0]);
                    }
                }
            }
        }

        // 
        // Parse text content
        //
        List<TokenText> pages;
        {
            if (!TryGetFatal(context, context.tokenText, "Expected dialog window text", out var tokenTextContext))
                return false;

            if (!TryCompileTokenText(tokenTextContext, out pages))
            {
                LogError(tokenTextContext, "Failed to compile dialog window text");
                return false;
            }
        }

        //
        // Create dialog window
        //
        messageDialog = new MessageDialog(identifier, speaker, pages);

        return true;
    }

    private static string ParseIdentifier(ITerminalNode identifierNode)
    {
        var text = identifierNode.Symbol.Text;
        if (text.StartsWith("``"))
        {
            // verbatim identifier
            // ``foo``
            // 0123456
            text = text.Substring(2, text.Length - 4);
        }

        return text;
    }

    private bool TryCompileSelectionDialog(MessageScriptParser.SelectionDialogContext context, out SelectionDialog selectionWindow)
    {
        LogContextInfo(context);

        selectionWindow = null;

        //
        // Parse identifier
        //
        string identifier;
        {
            if (!TryGetFatal(context, context.Identifier, "Expected selection window name", out var identifierNode))
                return false;

            identifier = ParseIdentifier(identifierNode);
        }

        LogInfo(context, $"Compiling selection window: {identifier}");

        //
        // Parse pattern
        //
        SelectionDialogPattern pattern = SelectionDialogPattern.Top;
        {
            if (TryGet(context, context.selectionDialogPattern, out var patternCtx))
            {
                if (TryGet(patternCtx, patternCtx.SelectionDialogPatternId, out var patternIdNode))
                {
                    switch (patternIdNode.Symbol.Text)
                    {
                        case "top": pattern = SelectionDialogPattern.Top; break;
                        case "bottom": pattern = SelectionDialogPattern.Bottom; break;
                        default:
                            LogError(patternCtx, $"Unknown selection dialog pattern: {patternIdNode.Symbol.Text}");
                            return false;
                    }
                }
                else if (TryParseShortIntLiteral(context, "Failed to parse selection dialog pattern ID", patternCtx.IntLiteral, out var patternId))
                {
                    pattern = (SelectionDialogPattern)patternId;
                }
                else
                {
                    LogError(patternCtx, "Invalid selection dialog pattern");
                    return false;
                }
            }
        }

        // 
        // Parse text content
        //
        List<TokenText> options;
        {
            if (!TryGetFatal(context, context.tokenText, "Expected selection window text", out var tagTextContext))
                return false;

            if (!TryCompileTokenText(tagTextContext, out options))
            {
                LogError(tagTextContext, "Failed to compile selection window text");
                return false;
            }
        }

        //
        // Create Selection window
        //
        selectionWindow = new SelectionDialog(identifier, pattern, options);

        return true;
    }

    private bool TryCompileTokenText(MessageScriptParser.TokenTextContext context, out List<TokenText> lines)
    {
        LogContextInfo(context);

        lines = new List<TokenText>();
        TokenTextBuilder lineBuilder = null;

        if (context.children != null)
        {
            foreach (var node in context.children)
            {
                IToken lineToken;

                if (TryCast<MessageScriptParser.TokenContext>(node, out var tagContext))
                {
                    if (!TryGetFatal(context, () => tagContext.Identifier(), "Expected tag id", out var tagIdNode))
                        return false;

                    var tagId = ParseIdentifier(tagIdNode);

                    switch (tagId.ToLowerInvariant())
                    {
                        case "f":
                            {
                                if (!TryCompileFunctionToken(tagContext, out var functionToken))
                                {
                                    mLogger.Error("Failed to compile function token");
                                    return false;
                                }

                                lineToken = functionToken;
                            }
                            break;

                        case "n":
                            lineToken = new NewLineToken();
                            break;

                        case "e":
                            {
                                if (lineBuilder == null)
                                {
                                    LogWarning(context, "Empty line");
                                    lines.Add(new TokenText());
                                }
                                else
                                {
                                    lines.Add(lineBuilder.Build());
                                    lineBuilder = null;
                                }

                                continue;
                            }

                        case "x":
                            {
                                if (!TryCompileCodePointToken(tagContext, out var codePointToken))
                                {
                                    mLogger.Error("Failed to compile code point token");
                                    return false;
                                }

                                lineToken = codePointToken;
                            }
                            break;

                        default:
                            {
                                lineToken = null;
                                var wasAliasedFunction = false;

                                if (Library != null)
                                {
                                    wasAliasedFunction = TryCompileAliasedFunction(tagContext, tagId, out var functionToken);
                                    lineToken = functionToken;
                                }

                                if (!wasAliasedFunction)
                                {
                                    LogError(tagContext, $"Unknown tag with id {tagId}");
                                    return false;
                                }
                                break;
                            }
                    }
                }
                else if (TryCast<ITerminalNode>(node, out var textNode))
                {
                    var text = textNode.Symbol.Text;

                    var textWithoutNewlines = text.Replace("\r", "").Replace("\n", "");
                    if (textWithoutNewlines.Length == 0)
                        continue; // filter out standalone newlines

                    lineToken = new StringToken(textWithoutNewlines);
                }
                else
                {
                    if (node is ParserRuleContext)
                    {
                        LogError(node as ParserRuleContext, "Expected a tag or text, but got neither.");
                    }
                    else
                    {
                        LogError(context, "Expected a tag or text, but got neither.");
                    }

                    return false;
                }

                if (lineBuilder == null)
                    lineBuilder = new TokenTextBuilder();

                Debug.Assert(lineToken != null, "Line token shouldn't be null");

                lineBuilder.AddToken(lineToken);
            }
        }

        if (lineBuilder != null)
        {
            lines.Add(lineBuilder.Build());
        }

        return true;
    }

    private bool TryCompileAliasedFunction(MessageScriptParser.TokenContext context, string tagId, out FunctionToken functionToken)
    {
        LogContextInfo(context);

        functionToken = new FunctionToken();
        var functionWasFound = false;

        foreach (var library in Library.MessageScriptLibraries)
        {
            var function = library.Functions.SingleOrDefault(x => x.Name == tagId);
            if (function == null)
                continue;

            var arguments = new List<ushort>();
            for (var i = 0; i < function.Parameters.Count; i++)
            {
                if (!TryParseUShortIntExpression(context, "Expected function argument", () => context.expression(i), out var argument))
                    return false;

                arguments.Add(argument);
            }

            functionToken = new FunctionToken(library.Index, function.Index, arguments);
            functionWasFound = true;
            break;
        }

        return functionWasFound;
    }

    private bool TryCompileFunctionToken(MessageScriptParser.TokenContext context, out FunctionToken functionToken)
    {
        LogContextInfo(context);

        functionToken = new FunctionToken();

        if (!TryGetFatal(context, context.expression, "Expected arguments", out var argumentNodes))
            return false;

        if (!TryParseUShortIntExpression(context, "Expected function table index", () => argumentNodes[0], out var functionTableIndex))
            return false;

        if (!TryParseUShortIntExpression(context, "Expected function index", () => argumentNodes[1], out var functionIndex))
            return false;

        if (argumentNodes.Length > 2)
        {
            var arguments = new List<ushort>(argumentNodes.Length - 2);
            for (int i = 2; i < argumentNodes.Length; i++)
            {
                if (!TryParseUShortIntExpression(context, "Expected function argument", () => argumentNodes[i], out var argument))
                    return false;

                arguments.Add(argument);
            }

            functionToken = new FunctionToken(functionTableIndex, functionIndex, arguments);
        }
        else
        {
            functionToken = new FunctionToken(functionTableIndex, functionIndex);
        }

        return true;
    }

    private bool TryCompileCodePointToken(MessageScriptParser.TokenContext context, out CodePointToken codePointToken)
    {
        LogContextInfo(context);

        codePointToken = new CodePointToken();

        if (!TryGetFatal(context, context.expression, "Expected code point surrogate pair", out var argumentNodes))
            return false;

        if (!TryParseByteIntLiteral(context, "Expected code point high surrogate", () => argumentNodes[0].IntLiteral(), out var highSurrogate))
            return false;

        if (!TryParseByteIntLiteral(context, "Expected code point low surrogate", () => argumentNodes[1].IntLiteral(), out var lowSurrogate))
            return false;

        codePointToken = new CodePointToken(highSurrogate, lowSurrogate);

        return true;
    }

    // Predicate helpers
    private bool TryGetFatal<T>(ParserRuleContext context, Func<T> getFunc, string errorText, out T value)
    {
        bool success = TryGet(context, getFunc, out value);

        if (!success)
            LogError(context, errorText);

        return success;
    }

    private bool TryGet<T>(ParserRuleContext context, Func<T> getFunc, out T value)
    {
        try
        {
            value = getFunc();
        }
        catch (Exception)
        {
            value = default(T);
            return false;
        }

        if (value == null)
            return false;

        return true;
    }

    private bool TryCast<T>(object obj, out T value) where T : class
    {
        value = obj as T;
        return value != null;
    }

    // Expression parsing
    private bool TryParseUShortIntExpression(ParserRuleContext context, string failureText, Func<MessageScriptParser.ExpressionContext> getFunc, out ushort value)
    {
        value = 0;

        if (!TryGetFatal(context, getFunc, failureText, out var expressionContext))
            return false;

        int intValue = 0;
        if (TryGet(expressionContext, expressionContext.IntLiteral, out var node))
        {
            if (!TryParseIntLiteral(node, out intValue))
                return false;
        }
        else if (TryGet(expressionContext, expressionContext.Identifier, out var identifier))
        {
            if (mVariables.TryGetValue(ParseIdentifier(identifier), out intValue))
                return false;
        }
        else
        {
            return false;
        }

        if (intValue < ushort.MinValue || intValue > ushort.MaxValue)
        {
            // Try to convert signed short to unsigned
            if (intValue >= short.MinValue && intValue <= short.MaxValue)
            {
                intValue = (ushort)((short)intValue);
            }
            else
            {
                LogError(expressionContext, $"Value out of range: {intValue}");
                return false;
            }
        }

        // Todo: range checking?
        value = (ushort)intValue;
        return true;
    }

    private bool TryParseShortIntExpression(ParserRuleContext context, string failureText, Func<MessageScriptParser.ExpressionContext> getFunc, out short value)
    {
        value = -1;

        if (!TryGetFatal(context, getFunc, failureText, out var expressionContext))
            return false;

        int intValue = 0;
        if (TryGet(expressionContext, expressionContext.IntLiteral, out var node))
        {
            if (!TryParseIntLiteral(node, out intValue))
                return false;
        }
        else if (TryGet(expressionContext, expressionContext.Identifier, out var identifier))
        {
            if (mVariables.TryGetValue(ParseIdentifier(identifier), out intValue))
                return false;
        }
        else
        {
            return false;
        }

        if (intValue < short.MinValue || intValue > short.MaxValue)
        {
            LogError(expressionContext, "Value out of range");
            return false;
        }

        // Todo: range checking?
        value = (short)intValue;
        return true;
    }

    private bool TryParseIntegerExpression(ParserRuleContext context, string failureText, Func<MessageScriptParser.ExpressionContext> getFunc, out int value)
    {
        value = -1;

        if (!TryGetFatal(context, getFunc, failureText, out var expressionContext))
            return false;

        if (TryGet(expressionContext, expressionContext.IntLiteral, out var node))
        {
            if (!TryParseIntLiteral(node, out value))
                return false;
        }
        else if (TryGet(expressionContext, expressionContext.Identifier, out var identifier))
        {
            if (mVariables.TryGetValue(ParseIdentifier(identifier), out value))
                return false;
        }
        else
        {
            return false;
        }

        return true;
    }

    // Int literal parsing
    private bool TryParseShortIntLiteral(ParserRuleContext context, string failureText, Func<ITerminalNode> getFunc, out short value)
    {
        value = -1;

        if (!TryGetFatal(context, getFunc, failureText, out var node))
            return false;

        if (!TryParseIntLiteral(node, out var intValue))
            return false;

        // Todo: range checking?
        value = (short)intValue;

        return true;
    }

    private bool TryParseByteIntLiteral(ParserRuleContext context, string failureText, Func<ITerminalNode> getFunc, out byte value)
    {
        value = 0;

        if (!TryGetFatal(context, getFunc, failureText, out var node))
            return false;

        if (!TryParseIntLiteral(node, out var intValue))
            return false;

        // Todo: range checking?
        value = (byte)intValue;

        return true;
    }

    private bool TryParseIntLiteral(ITerminalNode node, out int value)
    {
        bool succeeded;

        if (node.Symbol.Text.StartsWith("0x"))
        {
            succeeded = int.TryParse(node.Symbol.Text.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }
        else
        {
            succeeded = int.TryParse(node.Symbol.Text, out value);
        }

        if (!succeeded)
        {
            LogError(node.Symbol, "Invalid integer format");
        }

        return succeeded;
    }

    // Logging
    private void LogContextInfo(ParserRuleContext context)
    {
        mLogger.Trace($"({context.Start.Line:D4}:{context.Start.Column:D4}) Compiling {MessageScriptParser.ruleNames[context.RuleIndex]}");
    }

    private void LogInfo(ParserRuleContext context, string str)
    {
        mLogger.Info($"({context.Start.Line:D4}:{context.Start.Column:D4}) {str}");
    }

    private void LogInfo(string str)
    {
        mLogger.Info(str);
    }

    private void LogError(string str)
    {
        mLogger.Error(str);
    }

    private void LogError(ParserRuleContext context, string str)
    {
        mLogger.Error($"({context.Start.Line:D4}:{context.Start.Column:D4}) {str}");
    }

    private void LogError(Antlr4.Runtime.IToken token, string str)
    {
        mLogger.Error($"({token.Line:D4}:{token.Column:D4}) {str}");
    }

    private void LogWarning(string str)
    {
        mLogger.Warning(str);
    }

    private void LogWarning(ParserRuleContext context, string str)
    {
        mLogger.Warning($"({context.Start.Line:D4}:{context.Start.Column:D4}) {str}");
    }

    /// <summary>
    /// Antlr error listener for catching syntax errors while parsing.
    /// </summary>
    private class AntlrErrorListener : IAntlrErrorListener<Antlr4.Runtime.IToken>
    {
        private MessageScriptCompiler mCompiler;

        public AntlrErrorListener(MessageScriptCompiler compiler)
        {
            mCompiler = compiler;
        }

        public void SyntaxError(IRecognizer recognizer, Antlr4.Runtime.IToken offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
        {
            mCompiler.mLogger.Error($"Syntax error: {msg} ({offendingSymbol.Line}:{offendingSymbol.Column})");
        }
    }
}

[Serializable]
public class MessageScriptCompilationFailureException : Exception
{
    public MessageScriptCompilationFailureException()
        : base("Failed to compile message script")
    {
    }
}
