using Antlr4.Runtime;
using Antlr4.Runtime.Tree;
using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser.Grammar;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler.Parser;

/// <summary>
/// Represents a parser that turns ANTLR's parse tree into an abstract syntax tree (AST).
/// </summary>
public class CompilationUnitParser
{
    private readonly Logger mLogger;

    public CompilationUnitParser()
    {
        mLogger = new Logger(nameof(CompilationUnitParser));
    }

    /// <summary>
    /// Adds a parser log listener. Use this if you want to see what went wrong during parsing.
    /// </summary>
    /// <param name="listener">The listener to add.</param>
    public void AddListener(LogListener listener)
    {
        listener.Subscribe(mLogger);
    }

    /// <summary>
    /// Parse the given input source. An exception is thrown on failure.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <returns>The output of the parsing.</returns>
    public CompilationUnit Parse(string input)
    {
        if (!TryParse(input, out var script))
            throw new FlowScriptSyntaxParserFailureException();

        return script;
    }

    /// <summary>
    /// Parse the given input source. An exception is thrown on failure.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <returns>The output of the parsing.</returns>
    public CompilationUnit Parse(TextReader input)
    {
        if (!TryParse(input, out var script))
            throw new FlowScriptSyntaxParserFailureException();

        return script;
    }

    /// <summary>
    /// Parse the given input source. An exception is thrown on failure.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <returns>The output of the parsing.</returns>
    public CompilationUnit Parse(Stream input)
    {
        if (!TryParse(input, out var script))
            throw new FlowScriptSyntaxParserFailureException();

        return script;
    }

    /// <summary>
    /// Attempts to parse the given input source.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <param name="ast">The output of the parsing. Is only guaranteed to be valid if the operation succeeded.</param>
    /// <returns>A boolean value indicating whether the parsing succeeded or not.</returns>
    public bool TryParse(string input, out CompilationUnit ast)
    {
        var cst = FlowScriptParserHelper.ParseCompilationUnit(input);
        return TryParseCompilationUnit(cst, out ast);
    }

    /// <summary>
    /// Attempts to parse the given input source.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <param name="ast">The output of the parsing. Is only guaranteed to be valid if the operation succeeded.</param>
    /// <returns>A boolean value indicating whether the parsing succeeded or not.</returns>
    public bool TryParse(TextReader input, out CompilationUnit ast)
    {
        var cst = FlowScriptParserHelper.ParseCompilationUnit(input, new AntlrErrorListener(mLogger));
        return TryParseCompilationUnit(cst, out ast);
    }

    /// <summary>
    /// Attempts to parse the given input source.
    /// </summary>
    /// <param name="input">The input source.</param>
    /// <param name="ast">The output of the parsing. Is only guaranteed to be valid if the operation succeeded.</param>
    /// <returns>A boolean value indicating whether the parsing succeeded or not.</returns>
    public bool TryParse(Stream input, out CompilationUnit ast)
    {
        var cst = FlowScriptParserHelper.ParseCompilationUnit(input, new AntlrErrorListener(mLogger));
        return TryParseCompilationUnit(cst, out ast);
    }

    //
    // Parsing
    //
    private bool TryParseCompilationUnit(FlowScriptParser.CompilationUnitContext context, out CompilationUnit compilationUnit)
    {
        LogInfo("Parsing compilation unit");
        LogContextInfo(context);

        compilationUnit = CreateAstNode<CompilationUnit>(context);

        // Parse using statements
        if (TryGet(context, context.importStatement, out var importContexts))
        {
            List<Import> imports = null;
            if (!TryFunc(context, "Failed to parse imports", () => TryParseImports(importContexts, out imports)))
                return false;

            compilationUnit.Imports = imports;
        }

        // Parse declarations
        List<Declaration> statements = null;
        if (!TryFunc(context, "Failed to parse statement(s)", () => TryParseDeclarationStatements(context.declarationStatement(), out statements)))
            return false;

        compilationUnit.Declarations = statements;

        LogInfo("Done parsing compilation unit");
        return true;
    }

    //
    // Imports
    //
    private bool TryParseImports(FlowScriptParser.ImportStatementContext[] contexts, out List<Import> imports)
    {
        LogTrace("Start parsing import statements");
        imports = new List<Import>();

        foreach (var importContext in contexts)
        {
            Import import = null;
            if (!TryFunc(importContext, "Failed to parse import statement", () => TryParseImport(importContext, out import)))
                return false;

            imports.Add(import);
        }

        LogTrace("Done parsing imports");
        return true;
    }

    private bool TryParseImport(FlowScriptParser.ImportStatementContext context, out Import import)
    {
        LogContextInfo(context);

        import = null;

        if (!TryGet(context, "Expected file path", context.StringLiteral, out var filePathNode))
            return false;

        if (!TryGet(context, "Expected file path", () => filePathNode.Symbol.Text, out var filePath))
            return false;

        import = CreateAstNode<Import>(context);
        import.CompilationUnitFileName = filePath.Trim('"');

        LogTrace($"Parsed import: {import}");
        return true;
    }

    //
    // Statements
    //
    private bool TryParseStatements(FlowScriptParser.StatementContext[] contexts, out List<Statement> statements)
    {
        LogTrace("Parsing statements");
        statements = new List<Statement>();

        foreach (var context in contexts)
        {
            Statement statement = null;
            if (!TryFunc(context, "Failed to parse statement", () => TryParseStatement(context, out statement)))
                return false;

            statements.Add(statement);
        }

        LogTrace("Done parsing statements");
        return true;
    }

    private bool TryParseStatement(FlowScriptParser.StatementContext context, out Statement statement)
    {
        LogContextInfo(context);

        statement = null;

        // Parse declaration statement
        if (TryGet(context, context.nullStatement, out var nullStatementContext))
        {
            statement = CreateAstNode<NullStatement>(nullStatementContext);
        }
        else if (TryGet(context, context.compoundStatement, out var compoundStatementContext))
        {
            CompoundStatement compoundStatement = null;
            if (!TryFunc(compoundStatementContext, "Failed to parse compound statement", () => TryParseCompoundStatement(compoundStatementContext, out compoundStatement)))
                return false;

            statement = compoundStatement;
        }
        else if (TryGet(context, context.declarationStatement, out var declarationContext))
        {
            Declaration declaration = null;
            if (!TryFunc(declarationContext, "Failed to parse declaration", () => TryParseDeclaration(declarationContext, out declaration)))
                return false;

            statement = declaration;
        }
        else if (TryGet(context, context.expression, out var expressionContext))
        {
            Expression expression = null;
            if (!TryFunc(expressionContext, "Failed to parse expression", () => TryParseExpression(expressionContext, out expression)))
                return false;

            statement = expression;
        }
        else if (TryGet(context, context.ifStatement, out var ifStatementContext))
        {
            IfStatement ifStatement = null;
            if (!TryFunc(ifStatementContext, "Failed to parse if statement", () => TryParseIfStatement(ifStatementContext, out ifStatement)))
                return false;

            statement = ifStatement;
        }
        else if (TryGet(context, context.forStatement, out var forStatementContext))
        {
            ForStatement forStatement = null;
            if (!TryFunc(forStatementContext, "Failed to parse for statement", () => TryParseForStatement(forStatementContext, out forStatement)))
                return false;

            statement = forStatement;
        }
        else if (TryGet(context, context.whileStatement, out var whileStatementContext))
        {
            WhileStatement whileStatement = null;
            if (!TryFunc(whileStatementContext, "Failed to parse while statement", () => TryParseWhileStatement(whileStatementContext, out whileStatement)))
                return false;

            statement = whileStatement;
        }
        else if (TryGet(context, context.gotoStatement, out var gotoStatementContext))
        {
            GotoStatement gotoStatement = null;
            if (!TryFunc(ifStatementContext, "Failed to parse goto statement", () => TryParseGotoStatement(gotoStatementContext, out gotoStatement)))
                return false;

            statement = gotoStatement;
        }
        else if (TryGet(context, context.returnStatement, out var returnStatementContext))
        {
            ReturnStatement returnStatement = null;
            if (!TryFunc(ifStatementContext, "Failed to parse return statement", () => TryParseReturnStatement(returnStatementContext, out returnStatement)))
                return false;

            statement = returnStatement;
        }
        else if (TryGet(context, context.breakStatement, out var breakStatement))
        {
            statement = CreateAstNode<BreakStatement>(breakStatement);
        }
        else if (TryGet(context, context.continueStatement, out var continueStatement))
        {
            statement = CreateAstNode<ContinueStatement>(continueStatement);
        }
        else if (TryGet(context, context.switchStatement, out var switchStatementContext))
        {
            if (!TryParseSwitchStatement(switchStatementContext, out var switchStatement))
            {
                LogError(switchStatementContext, "Failed to parse switch statement");
                return false;
            }

            statement = switchStatement;
        }
        else
        {
            LogError(context, "Expected statement");
            return false;
        }

        return true;
    }

    private bool TryParseCompoundStatement(FlowScriptParser.CompoundStatementContext context, out CompoundStatement body)
    {
        LogTrace("Parsing compound statement");
        LogContextInfo(context);

        body = CreateAstNode<CompoundStatement>(context);

        if (!TryGet(context, "Expected statement(s)", context.statement, out var statementContexts))
            return false;

        List<Statement> statements = null;
        if (!TryFunc(context, "Failed to parse statement(s)", () => TryParseStatements(statementContexts, out statements)))
            return false;

        body.Statements.AddRange(statements);

        LogTrace("Done parsing compound statement");
        return true;
    }

    //
    // Declaration statements
    //
    private bool TryParseDeclarationStatements(FlowScriptParser.DeclarationStatementContext[] contexts, out List<Declaration> statements)
    {
        LogTrace("Parsing declarations");
        statements = new List<Declaration>();

        foreach (var context in contexts)
        {
            Declaration statement = null;
            if (!TryFunc(context, "Failed to parse declaration", () => TryParseDeclaration(context, out statement)))
                return false;

            statements.Add(statement);
        }

        LogTrace("Done parsing declarations");
        return true;
    }

    private bool TryParseDeclaration(FlowScriptParser.DeclarationStatementContext context, out Declaration declaration)
    {
        LogContextInfo(context);

        declaration = null;

        // Parse function declaration statement
        if (TryGet(context, context.functionDeclarationStatement, out var functionDeclarationContext))
        {
            FunctionDeclaration functionDeclaration = null;
            if (!TryFunc(functionDeclarationContext, "Failed to parse function declaration", () => TryParseFunctionDeclaration(functionDeclarationContext, out functionDeclaration)))
                return false;

            declaration = functionDeclaration;
        }
        else if (TryGet(context, context.procedureDeclarationStatement, out var procedureDeclarationContext))
        {
            ProcedureDeclaration procedureDeclaration = null;
            if (!TryFunc(procedureDeclarationContext, "Failed to parse procedure declaration", () => TryParseProcedureDeclaration(procedureDeclarationContext, out procedureDeclaration)))
                return false;

            declaration = procedureDeclaration;
        }
        else if (TryGet(context, context.variableDeclarationStatement, out var variableDeclarationContext))
        {
            VariableDeclaration variableDeclaration = null;
            if (!TryFunc(variableDeclarationContext, "Failed to parse variable declaration", () => TryParseVariableDeclaration(variableDeclarationContext, out variableDeclaration)))
                return false;

            declaration = variableDeclaration;
        }
        else if (TryGet(context, context.enumTypeDeclarationStatement, out var enumDeclarationContext))
        {
            EnumDeclaration enumDeclaration = null;
            if (!TryFunc(enumDeclarationContext, "Failed to parse enum declaration", () => TryParseEnumDeclaration(enumDeclarationContext, out enumDeclaration)))
                return false;

            declaration = enumDeclaration;
        }
        else if (TryGet(context, context.labelDeclarationStatement, out var labelDeclarationContext))
        {
            LabelDeclaration labelDeclaration = null;
            if (!TryFunc(labelDeclarationContext, "Failed to parse label declaration", () => TryParseLabelDeclaration(labelDeclarationContext, out labelDeclaration)))
                return false;

            declaration = labelDeclaration;
        }
        else
        {
            LogError(context, "Expected function, procedure or variable declaration");
            return false;
        }

        return true;
    }

    private bool TryParseFunctionDeclaration(FlowScriptParser.FunctionDeclarationStatementContext context, out FunctionDeclaration functionDeclaration)
    {
        LogTrace("Parsing function declaration");
        LogContextInfo(context);

        functionDeclaration = CreateAstNode<FunctionDeclaration>(context);

        // Parse return type
        {
            if (!TryGet(context, "Expected function return type", () => context.TypeIdentifier(), out var typeIdentifierNode))
            {
                return false;
            }

            TypeIdentifier typeIdentifier = null;
            if (!TryFunc(typeIdentifierNode, "Failed to parse function return type identifier", () => TryParseTypeIdentifier(typeIdentifierNode, out typeIdentifier)))
                return false;

            functionDeclaration.ReturnType = typeIdentifier;
        }

        // Parse index
        {
            if (!TryGet(context, "Expected function index", context.IntLiteral, out var indexNode))
                return false;

            IntLiteral indexIntLiteral = null;
            if (!TryFunc(indexNode, "Failed to parse function index", () => TryParseIntLiteral(indexNode, out indexIntLiteral)))
                return false;

            functionDeclaration.Index = indexIntLiteral;
        }

        // Parse identifier
        {
            if (!TryGet(context, "Expected function identifier", () => context.Identifier(), out var identifierNode))
                return false;

            Identifier identifier = null;
            if (!TryFunc(identifierNode, "Failed to parse function identifier", () => TryParseIdentifier(identifierNode, out identifier)))
                return false;

            identifier.ExpressionValueKind = ValueKind.Function;

            functionDeclaration.Identifier = identifier;
        }

        // Parse parameter list
        {
            if (!TryGet(context, "Expected function parameter list", context.parameterList, out var parameterListContext))
                return false;

            List<Parameter> parameters = null;
            if (!TryFunc(parameterListContext, "Failed to parse function parameter list", () => TryParseParameterList(parameterListContext, out parameters)))
                return false;

            functionDeclaration.Parameters = parameters;
        }

        LogInfo($"Parsed function declaration for '{functionDeclaration.Identifier.Text}'");
        return true;
    }

    private bool TryParseProcedureDeclaration(FlowScriptParser.ProcedureDeclarationStatementContext context, out ProcedureDeclaration procedureDeclaration)
    {
        LogTrace("Start parsing procedure declaration");
        LogContextInfo(context);

        procedureDeclaration = CreateAstNode<ProcedureDeclaration>(context);

        // Parse return type
        int identifierIndex = 0;
        if (!TryGet(context, "Expected function return type", context.TypeIdentifier, out var typeIdentifierNode))
        {
            return false;
        }

        TypeIdentifier typeIdentifier = null;
        if (!TryFunc(typeIdentifierNode, "Failed to parse procedure return type identifier", () => TryParseTypeIdentifier(typeIdentifierNode, out typeIdentifier)))
            return false;

        procedureDeclaration.ReturnType = typeIdentifier;

        // Parse identifier

        if (!TryGet(context, "Expected procedure identifier", () => context.Identifier(), out var identifierNode))
            return false;

        Identifier identifier = null;
        if (!TryFunc(identifierNode, "Failed to parse procedure identifier", () => TryParseIdentifier(identifierNode, out identifier)))
            return false;

        identifier.ExpressionValueKind = ValueKind.Procedure;
        procedureDeclaration.Identifier = identifier;
        LogInfo($"Parsing procedure '{identifier.Text}'");

        // Parse parameter list
        if (!TryGet(context, "Expected procedure parameter list", context.parameterList, out var parameterListContext))
            return false;

        List<Parameter> parameters = null;
        if (!TryFunc(parameterListContext, "Failed to parse procedure parameter list", () => TryParseParameterList(parameterListContext, out parameters)))
            return false;

        procedureDeclaration.Parameters = parameters;

        // Parse body
        if (TryGet(context, context.compoundStatement, out var compoundStatementContext))
        {
            CompoundStatement body = null;
            if (!TryFunc(compoundStatementContext, "Failed to parse procedure body", () => TryParseCompoundStatement(compoundStatementContext, out body)))
                return false;

            procedureDeclaration.Body = body;
        }

        LogTrace($"Done parsing procedure declaration: {procedureDeclaration}");
        return true;
    }

    private bool TryParseVariableDeclaration(FlowScriptParser.VariableDeclarationStatementContext context, out VariableDeclaration variableDeclaration)
    {
        LogTrace("Parsing variable declaration");
        LogContextInfo(context);

        bool isArray = context.arraySignifier() != null;
        if (!isArray)
            variableDeclaration = CreateAstNode<VariableDeclaration>(context);
        else
            variableDeclaration = CreateAstNode<ArrayVariableDeclaration>(context);

        // Parse modifier(s)
        if (TryGet(context, context.variableModifier, out var variableModifierContext))
        {
            if (!TryParseVariableModifier(variableModifierContext, out var modifier))
            {
                LogError(variableModifierContext, "Failed to parse variable modifier");
                return false;
            }

            variableDeclaration.Modifier = modifier;
        }

        // Parse type identifier
        {
            if (!TryGet(context, "Expected function return type", () => context.TypeIdentifier(), out var typeIdentifierNode))
            {
                return false;
            }

            TypeIdentifier typeIdentifier = null;
            if (!TryFunc(typeIdentifierNode, "Failed to parse variable type identifier", () => TryParseTypeIdentifier(typeIdentifierNode, out typeIdentifier)))
                return false;

            variableDeclaration.Type = typeIdentifier;
        }

        // Parse identifier
        {
            if (!TryGet(context, "Expected variable identifier", () => context.Identifier(), out var identifierNode))
                return false;

            Identifier identifier = null;
            if (!TryFunc(identifierNode, "Failed to parse variable identifier", () => TryParseIdentifier(identifierNode, out identifier)))
                return false;

            // Resolve the identifier value type as it's known
            identifier.ExpressionValueKind = variableDeclaration.Type.ValueKind;

            variableDeclaration.Identifier = identifier;
        }

        // Parse expression
        if (TryGet(context, context.expression, out var expressionContext))
        {
            Expression initializer = null;
            if (!TryFunc(expressionContext, "Failed to parse variable initializer", () => TryParseExpression(expressionContext, out initializer)))
                return false;

            variableDeclaration.Initializer = initializer;
        }

        if (isArray)
        {
            // Parse size
            var sizeLiteral = context.arraySignifier().IntLiteral();
            if (!(sizeLiteral != null && TryParseIntLiteral(sizeLiteral, out var size)))
            {
                var arrayInitializer = variableDeclaration.Initializer as InitializerList;
                if (arrayInitializer == null)
                {
                    LogError(context, "Expected initializer list");
                    return false;
                }

                size = arrayInitializer.Expressions.Count;
            }

            ((ArrayVariableDeclaration)variableDeclaration).Size = size;
        }

        LogTrace($"Done parsing variable declaration: {variableDeclaration}");
        return true;
    }

    private bool TryParseVariableModifier(FlowScriptParser.VariableModifierContext context, out VariableModifier modifier)
    {
        if (TryGet(context, context.Global, out var staticNode))
        {
            modifier = CreateAstNode<VariableModifier>(staticNode);
            modifier.Kind = VariableModifierKind.Global;
        }
        else if (TryGet(context, context.Const, out var constNode))
        {
            modifier = CreateAstNode<VariableModifier>(constNode);
            modifier.Kind = VariableModifierKind.Constant;
        }
        else if (TryGet(context, context.AiLocal, out var aiLocalNode))
        {
            modifier = CreateAstNode<VariableModifier>(aiLocalNode);
            modifier.Kind = VariableModifierKind.AiLocal;
        }
        else if (TryGet(context, context.AiGlobal, out var aiGlobalNode))
        {
            modifier = CreateAstNode<VariableModifier>(aiGlobalNode);
            modifier.Kind = VariableModifierKind.AiGlobal;
        }
        else if (TryGet(context, context.Bit, out var bitNode))
        {
            modifier = CreateAstNode<VariableModifier>(bitNode);
            modifier.Kind = VariableModifierKind.Bit;
        }
        else if (TryGet(context, context.Count, out var countNode))
        {
            modifier = CreateAstNode<VariableModifier>(countNode);
            modifier.Kind = VariableModifierKind.Count;
        }
        else
        {
            LogError(context, "Invalid variable modifier");
            modifier = null;
            return false;
        }

        if (!TryParseVariableModifierIndex(context, modifier))
            return false;

        LogTrace($"Parsed variable modifier: {modifier}");
        return true;
    }

    private bool TryParseVariableModifierIndex(FlowScriptParser.VariableModifierContext context, VariableModifier modifier)
    {
        if (TryGet(context, context.IntLiteral, out var indexNode))
        {
            if (!TryParseIntLiteral(indexNode, out var index))
            {
                LogError(indexNode.Symbol, "Invalid variable index");
                return false;
            }

            modifier.Index = index;
        }

        return true;
    }

    private bool TryParseEnumDeclaration(FlowScriptParser.EnumTypeDeclarationStatementContext context, out EnumDeclaration enumDeclaration)
    {
        LogContextInfo(context);

        enumDeclaration = CreateAstNode<EnumDeclaration>(context);

        // Parse identifier
        Identifier identifier = null;
        if (!TryFunc(context.Identifier(), "Failed to parse enum identifier", () => TryParseIdentifier(context.Identifier(), out identifier)))
            return false;

        enumDeclaration.Identifier = identifier;
        LogInfo($"Parsing enum '{identifier.Text}'");

        // Parse values
        List<EnumValueDeclaration> values = null;
        if (!TryFunc(context.enumValueList(), "Failed to parse enum values", () => TryParseEnumValueList(context.enumValueList(), out values)))
            return false;

        enumDeclaration.Values = values;

        LogTrace($"Parsed enum declaration: {enumDeclaration}");
        return true;
    }

    private bool TryParseEnumValueList(FlowScriptParser.EnumValueListContext context, out List<EnumValueDeclaration> values)
    {
        LogTrace("Parsing enum value list");
        values = new List<EnumValueDeclaration>();

        foreach (var valueContext in context.enumValueDeclaration())
        {
            var value = CreateAstNode<EnumValueDeclaration>(valueContext);

            // Parse identifier
            Identifier identifier = null;
            if (!TryFunc(valueContext.Identifier(), "Failed to parse enum value identifier", () => TryParseIdentifier(valueContext.Identifier(), out identifier)))
                return false;

            value.Identifier = identifier;

            if (valueContext.expression() != null)
            {
                // Parse value expression
                Expression enumValue = null;

                if (!TryFunc(valueContext.expression(), "Failed to parse enum value", () => TryParseExpression(valueContext.expression(), out enumValue)))
                    return false;

                value.Value = enumValue;
            }

            LogTrace($"Parsed enum value: {value}");
            values.Add(value);
        }

        LogTrace("Done parsing enum value list");

        return true;
    }

    private bool TryParseLabelDeclaration(FlowScriptParser.LabelDeclarationStatementContext context, out LabelDeclaration labelDeclaration)
    {
        LogContextInfo(context);

        labelDeclaration = CreateAstNode<LabelDeclaration>(context);

        // Parse identifier
        Identifier identifier = null;
        if (!TryFunc(context.Identifier(), "Failed to parse label identifier", () => TryParseIdentifier(context.Identifier(), out identifier)))
            return false;

        labelDeclaration.Identifier = identifier;

        LogTrace($"Parsed label declaration: {labelDeclaration}");

        return true;
    }

    //
    // Expressions
    //
    internal bool TryParseExpression(FlowScriptParser.ExpressionContext context, out Expression expression)
    {
        LogContextInfo(context);

        expression = null;

        // Parse null expression
        if (TryCast<FlowScriptParser.NullExpressionContext>(context, out var nullExpressionContext))
        {
            mLogger.Error("Null expression");
            expression = null;
        }
        else if (TryCast<FlowScriptParser.CompoundExpressionContext>(context, out var compoundExpressionContext))
        {
            if (!TryParseExpression(compoundExpressionContext.expression(), out expression))
                return false;
        }
        else if (TryCast<FlowScriptParser.InitializerListExpressionContext>(context, out var initializerListContext))
        {
            var initializerList = CreateAstNode<InitializerList>(initializerListContext);
            foreach (var expressionContext in initializerListContext.expression())
            {
                if (!TryParseExpression(expressionContext, out var expr))
                    return false;

                initializerList.Expressions.Add(expr);
            }

            expression = initializerList;
        }
        else if (TryCast<FlowScriptParser.SubscriptExpressionContext>(context, out var subscriptExpressionContext))
        {
            var subscriptOperator = CreateAstNode<SubscriptOperator>(subscriptExpressionContext);
            if (!TryParseIdentifier(subscriptExpressionContext.Identifier(), out var operand))
            {
                return false;
            }

            subscriptOperator.Operand = operand;

            if (!TryParseExpression(subscriptExpressionContext.expression(), out var indexExpression))
            {
                return false;
            }

            subscriptOperator.Index = indexExpression;
            expression = subscriptOperator;
        }
        else if (TryCast<FlowScriptParser.CastExpressionContext>(context, out var castExpressionContext))
        {
            mLogger.Error("Todo: cast");
            return false;
        }
        else if (TryCast<FlowScriptParser.MemberAccessExpressionContext>(context, out var memberAccessExpressionContext))
        {
            MemberAccessExpression memberAccessExpression = null;
            if (!TryFunc(memberAccessExpressionContext, "Failed to parse member access operator", () => TryParseMemberAccessExpression(memberAccessExpressionContext, out memberAccessExpression)))
                return false;

            expression = memberAccessExpression;
        }
        else if (TryCast<FlowScriptParser.CallExpressionContext>(context, out var callExpressionContext))
        {
            CallOperator callExpression = null;
            if (!TryFunc(callExpressionContext, "Failed to parse call operator", () => TryParseCallExpression(callExpressionContext, out callExpression)))
                return false;

            expression = callExpression;
        }
        else if (TryCast<FlowScriptParser.UnaryPostfixExpressionContext>(context, out var unaryPostfixExpressionContext))
        {
            UnaryExpression unaryExpression = null;
            if (!TryFunc(unaryPostfixExpressionContext, "Failed to parse unary postfix expression", () => TryParseUnaryPostfixExpression(unaryPostfixExpressionContext, out unaryExpression)))
                return false;

            expression = unaryExpression;
        }
        else if (TryCast<FlowScriptParser.UnaryPrefixExpressionContext>(context, out var unaryPrefixExpressionContext))
        {
            UnaryExpression unaryExpression = null;
            if (!TryFunc(unaryPrefixExpressionContext, "Failed to parse unary prefix expression", () => TryParseUnaryPrefixExpression(unaryPrefixExpressionContext, out unaryExpression)))
                return false;

            expression = unaryExpression;
        }
        else if (TryCast<FlowScriptParser.MultiplicationExpressionContext>(context, out var multiplicationExpressionContext))
        {
            BinaryExpression binaryExpression = null;
            if (!TryFunc(multiplicationExpressionContext, "Failed to parse multiplication expression", () => TryParseMultiplicationExpression(multiplicationExpressionContext, out binaryExpression)))
                return false;

            expression = binaryExpression;
        }
        else if (TryCast<FlowScriptParser.AdditionExpressionContext>(context, out var additionExpressionContext))
        {
            BinaryExpression binaryExpression = null;
            if (!TryFunc(additionExpressionContext, "Failed to parse addition expression", () => TryParseAdditionExpression(additionExpressionContext, out binaryExpression)))
                return false;

            expression = binaryExpression;
        }
        else if (TryCast<FlowScriptParser.RelationalExpressionContext>(context, out var relationalExpressionContext))
        {
            BinaryExpression binaryExpression = null;
            if (!TryFunc(relationalExpressionContext, "Failed to parse relational expression", () => TryParseRelationalExpression(relationalExpressionContext, out binaryExpression)))
                return false;

            expression = binaryExpression;
        }
        else if (TryCast<FlowScriptParser.EqualityExpressionContext>(context, out var equalityExpressionContext))
        {
            BinaryExpression equalityExpression = null;
            if (!TryFunc(equalityExpressionContext, "Failed to parse equality expression", () => TryParseEqualityExpression(equalityExpressionContext, out equalityExpression)))
                return false;

            expression = equalityExpression;
        }
        else if (TryCast<FlowScriptParser.LogicalAndExpressionContext>(context, out var logicalAndExpressionContext))
        {
            BinaryExpression binaryExpression = null;
            if (!TryFunc(logicalAndExpressionContext, "Failed to parse logical and expression", () => TryParseLogicalAndExpression(logicalAndExpressionContext, out binaryExpression)))
                return false;

            expression = binaryExpression;
        }
        else if (TryCast<FlowScriptParser.LogicalOrExpressionContext>(context, out var logicalOrExpressionContext))
        {
            BinaryExpression binaryExpression = null;
            if (!TryFunc(logicalOrExpressionContext, "Failed to parse logical or expression", () => TryParseLogicalOrExpression(logicalOrExpressionContext, out binaryExpression)))
                return false;

            expression = binaryExpression;
        }
        else if (TryCast<FlowScriptParser.AssignmentExpressionContext>(context, out var assignmentExpressionContext))
        {
            BinaryExpression binaryExpression = null;
            if (!TryFunc(assignmentExpressionContext, "Failed to parse assigment expression", () => TryParseAssignmentExpression(assignmentExpressionContext, out binaryExpression)))
                return false;

            expression = binaryExpression;
        }
        else if (TryCast<FlowScriptParser.PrimaryExpressionContext>(context, out var primaryExpressionContext))
        {
            Expression primaryExpression = null;
            if (!TryFunc(primaryExpressionContext, "Failed to parse primary expression", () => TryParsePrimaryExpression(primaryExpressionContext, out primaryExpression)))
                return false;

            expression = primaryExpression;
        }
        else
        {
            LogError(context, "Unknown expression");
            return false;
        }

        return true;
    }

    private bool TryParseMemberAccessExpression(FlowScriptParser.MemberAccessExpressionContext context, out MemberAccessExpression memberAccessExpression)
    {
        memberAccessExpression = CreateAstNode<MemberAccessExpression>(context);

        Identifier operand = null;
        if (!TryFunc(context.Identifier(0), "Failed to parse member access operand", () => TryParseIdentifier(context.Identifier(0), out operand)))
            return false;

        memberAccessExpression.Operand = operand;

        Identifier member = null;
        if (!TryFunc(context.Identifier(1), "Failed to parse member identifier", () => TryParseIdentifier(context.Identifier(1), out member)))
            return false;

        memberAccessExpression.Member = member;

        LogTrace($"Parsed member access expression: {memberAccessExpression}");

        return true;
    }

    private bool TryParseCallExpression(FlowScriptParser.CallExpressionContext context, out CallOperator callExpression)
    {
        LogContextInfo(context);

        callExpression = CreateAstNode<CallOperator>(context);

        if (!TryGet(context, "Expected function or procedure identifier", context.Identifier, out var identifierNode))
            return false;

        Identifier identifier = null;
        if (!TryFunc(identifierNode, "Failed to parse function or procedure identifier", () => TryParseIdentifier(identifierNode, out identifier)))
            return false;

        callExpression.Identifier = identifier;

        LogTrace($"Parsing call expression: {identifier}( ... )");

        if (TryGet(context, context.argumentList, out var argumentListContext))
        {
            if (!TryGet(argumentListContext, "Expected arguments(s)", () => argumentListContext.argument(), out var argumentContexts))
                return false;

            foreach (var argumentContext in argumentContexts)
            {
                Argument argument = null;
                if (!TryFunc(argumentContext, "Failed to parse argument", () => TryParseArgument(argumentContext, out argument)))
                    return false;

                callExpression.Arguments.Add(argument);
            }
        }

        LogTrace($"Parsed call expression: {callExpression}");

        return true;
    }

    private bool TryParseUnaryPostfixExpression(FlowScriptParser.UnaryPostfixExpressionContext context, out UnaryExpression unaryExpression)
    {
        LogContextInfo(context);

        switch (context.Op.Text)
        {
            case "--":
                unaryExpression = CreateAstNode<PostfixDecrementOperator>(context);
                break;

            case "++":
                unaryExpression = CreateAstNode<PostfixIncrementOperator>(context);
                break;

            default:
                unaryExpression = null;
                LogError(context, $"Invalid op for unary postfix expression: ${context.Op}");
                return false;
        }

        if (!TryParseExpression(context.expression(), out var leftExpression))
            return false;

        unaryExpression.Operand = leftExpression;

        LogTrace($"Parsed unary expression: {unaryExpression}");

        return true;
    }

    private bool TryParseUnaryPrefixExpression(FlowScriptParser.UnaryPrefixExpressionContext context, out UnaryExpression unaryExpression)
    {
        LogContextInfo(context);

        switch (context.Op.Text)
        {
            case "!":
                unaryExpression = CreateAstNode<LogicalNotOperator>(context);
                break;

            case "-":
                unaryExpression = CreateAstNode<NegationOperator>(context);
                break;

            case "--":
                unaryExpression = CreateAstNode<PrefixDecrementOperator>(context);
                break;

            case "++":
                unaryExpression = CreateAstNode<PrefixIncrementOperator>(context);
                break;

            default:
                unaryExpression = null;
                LogError(context, $"Invalid op for unary prefix expression: ${context.Op}");
                return false;
        }

        if (!TryParseExpression(context.expression(), out var leftExpression))
            return false;

        unaryExpression.Operand = leftExpression;

        LogTrace($"Parsed unary prefix expression: {unaryExpression}");

        return true;
    }

    private bool TryParseMultiplicationExpression(FlowScriptParser.MultiplicationExpressionContext context, out BinaryExpression binaryExpression)
    {
        LogContextInfo(context);

        switch (context.Op.Text)
        {
            case "*":
                binaryExpression = CreateAstNode<MultiplicationOperator>(context);
                break;
            case "/":
                binaryExpression = CreateAstNode<DivisionOperator>(context);
                break;
            case "%":
                binaryExpression = CreateAstNode<ModulusOperator>(context);
                break;
            default:
                binaryExpression = null;
                LogError(context, $"Invalid op for multiplication expression: ${context.Op}");
                return false;
        }

        // Left

        if (!TryParseExpression(context.expression(0), out var leftExpression))
            return false;

        binaryExpression.Left = leftExpression;

        // Right

        if (!TryParseExpression(context.expression(1), out var rightExpression))
            return false;

        binaryExpression.Right = rightExpression;

        LogTrace($"Parsed multiplication expression: {binaryExpression}");

        return true;
    }

    private bool TryParseAdditionExpression(FlowScriptParser.AdditionExpressionContext context, out BinaryExpression binaryExpression)
    {
        LogContextInfo(context);

        if (context.Op.Text == "+")
        {
            binaryExpression = CreateAstNode<AdditionOperator>(context);
        }
        else if (context.Op.Text == "-")
        {
            binaryExpression = CreateAstNode<SubtractionOperator>(context);
        }
        else
        {
            binaryExpression = null;
            LogError(context, $"Invalid op for addition expression: ${context.Op}");
            return false;
        }

        // Left
        {
            if (!TryParseExpression(context.expression(0), out var leftExpression))
                return false;

            binaryExpression.Left = leftExpression;
        }

        // Right
        {
            if (!TryParseExpression(context.expression(1), out var rightExpression))
                return false;

            binaryExpression.Right = rightExpression;
        }

        LogTrace($"Parsed addition expression: {binaryExpression}");

        return true;
    }

    private bool TryParseRelationalExpression(FlowScriptParser.RelationalExpressionContext context, out BinaryExpression binaryExpression)
    {
        LogContextInfo(context);

        switch (context.Op.Text)
        {
            case "<":
                binaryExpression = CreateAstNode<LessThanOperator>(context);
                break;
            case ">":
                binaryExpression = CreateAstNode<GreaterThanOperator>(context);
                break;
            case "<=":
                binaryExpression = CreateAstNode<LessThanOrEqualOperator>(context);
                break;
            case ">=":
                binaryExpression = CreateAstNode<GreaterThanOrEqualOperator>(context);
                break;
            default:
                binaryExpression = null;
                LogError(context, $"Invalid op for addition expression: ${context.Op}");
                return false;
        }

        // Left
        {
            if (!TryParseExpression(context.expression(0), out var leftExpression))
                return false;

            binaryExpression.Left = leftExpression;
        }

        // Right
        {
            if (!TryParseExpression(context.expression(1), out var rightExpression))
                return false;

            binaryExpression.Right = rightExpression;
        }

        LogTrace($"Parsed relational expression: {binaryExpression}");

        return true;
    }

    private bool TryParseEqualityExpression(FlowScriptParser.EqualityExpressionContext context, out BinaryExpression equalityExpression)
    {
        LogContextInfo(context);

        switch (context.Op.Text)
        {
            case "==":
                equalityExpression = CreateAstNode<EqualityOperator>(context);
                break;
            case "!=":
                equalityExpression = CreateAstNode<NonEqualityOperator>(context);
                break;
            default:
                equalityExpression = null;
                LogError(context, $"Invalid op for equality expression: ${context.Op}");
                return false;
        }

        // Left
        {
            if (!TryParseExpression(context.expression(0), out var leftExpression))
                return false;

            equalityExpression.Left = leftExpression;
        }

        // Right
        {
            if (!TryParseExpression(context.expression(1), out var rightExpression))
                return false;

            equalityExpression.Right = rightExpression;
        }

        LogTrace($"Parsed equality expression: {equalityExpression}");

        return true;
    }

    private bool TryParseLogicalAndExpression(FlowScriptParser.LogicalAndExpressionContext context, out BinaryExpression binaryExpression)
    {
        LogContextInfo(context);

        binaryExpression = CreateAstNode<LogicalAndOperator>(context);

        // Left
        {
            if (!TryParseExpression(context.expression(0), out var leftExpression))
                return false;

            binaryExpression.Left = leftExpression;
        }

        // Right
        {
            if (!TryParseExpression(context.expression(1), out var rightExpression))
                return false;

            binaryExpression.Right = rightExpression;
        }

        LogTrace($"Parsed logical and expression: {binaryExpression}");

        return true;
    }

    private bool TryParseLogicalOrExpression(FlowScriptParser.LogicalOrExpressionContext context, out BinaryExpression binaryExpression)
    {
        LogContextInfo(context);

        binaryExpression = CreateAstNode<LogicalOrOperator>(context);

        // Left
        {
            if (!TryParseExpression(context.expression(0), out var leftExpression))
                return false;

            binaryExpression.Left = leftExpression;
        }

        // Right
        {
            if (!TryParseExpression(context.expression(1), out var rightExpression))
                return false;

            binaryExpression.Right = rightExpression;
        }

        LogTrace($"Parsed relational expression: {binaryExpression}");

        return true;
    }

    private bool TryParseAssignmentExpression(FlowScriptParser.AssignmentExpressionContext context, out BinaryExpression binaryExpression)
    {
        LogContextInfo(context);

        switch (context.Op.Text)
        {
            case "=":
                binaryExpression = CreateAstNode<AssignmentOperator>(context);
                break;

            case "+=":
                binaryExpression = CreateAstNode<AdditionAssignmentOperator>(context);
                break;

            case "-=":
                binaryExpression = CreateAstNode<SubtractionAssignmentOperator>(context);
                break;

            case "*=":
                binaryExpression = CreateAstNode<MultiplicationAssignmentOperator>(context);
                break;

            case "/=":
                binaryExpression = CreateAstNode<DivisionAssignmentOperator>(context);
                break;

            case "%=":
                binaryExpression = CreateAstNode<ModulusAssignmentOperator>(context);
                break;

            default:
                LogError(context, $"Unknown assignment operator: {context.Op.Text}");
                binaryExpression = null;
                return false;
        }

        // Left
        {
            if (!TryParseExpression(context.expression(0), out var leftExpression))
                return false;

            binaryExpression.Left = leftExpression;
        }

        // Right
        {
            if (!TryParseExpression(context.expression(1), out var rightExpression))
                return false;

            binaryExpression.Right = rightExpression;
        }

        LogTrace($"Parsed assignment expression: {binaryExpression}");

        return true;
    }

    private bool TryParsePrimaryExpression(FlowScriptParser.PrimaryExpressionContext context, out Expression expression)
    {
        LogContextInfo(context);

        expression = null;
        if (!TryGet(context, "Expected primary expression", context.primary, out var primaryContext))
            return false;

        if (TryCast<FlowScriptParser.ConstantExpressionContext>(primaryContext, out var constantExpressionContext))
        {
            Expression constantExpression = null;
            if (!TryFunc(constantExpressionContext, "Failed to parse constant expression", () => TryParseConstantExpression(constantExpressionContext, out constantExpression)))
                return false;

            expression = constantExpression;
        }
        else if (TryCast<FlowScriptParser.IdentifierExpressionContext>(primaryContext, out var identifierExpressionContext))
        {
            Identifier identifier = null;
            if (!TryFunc(identifierExpressionContext, "Failed to parse identifier expression", () => TryParseIdentifierExpression(identifierExpressionContext, out identifier)))
                return false;

            expression = identifier;
        }
        else
        {
            LogError(primaryContext, "Expected constant or identifier expression");
            return false;
        }

        return true;
    }

    private bool TryParseConstantExpression(FlowScriptParser.ConstantExpressionContext context, out Expression expression)
    {
        LogContextInfo(context);

        expression = null;
        if (!TryGet(context, "Expected constant", context.constant, out var constantContext))
            return false;

        Expression constantExpression = null;
        if (!TryFunc(constantContext, "Failed to parse literal", () => TryParseLiteral(constantContext, out constantExpression)))
            return false;

        expression = constantExpression;

        LogTrace($"Parsed primary constant expression: {expression}");

        return true;
    }

    private bool TryParseIdentifierExpression(FlowScriptParser.IdentifierExpressionContext context, out Identifier identifier)
    {
        LogContextInfo(context);

        identifier = null;

        if (!TryGet(context, "Expected identifier", context.Identifier, out var identifierNode))
            return false;

        Identifier parsedIdentifier = null;
        if (!TryFunc(identifierNode, "Failed to parse identifier", () => TryParseIdentifier(identifierNode, out parsedIdentifier)))
            return false;

        identifier = parsedIdentifier;

        LogTrace($"Parsed primary identifier expression: {identifier}");

        return true;
    }

    //
    // Literals
    //
    private bool TryParseLiteral(FlowScriptParser.ConstantContext context, out Expression expression)
    {
        LogContextInfo(context);

        expression = null;
        if (TryGet(context, context.BoolLiteral, out var boolLiteralContext))
        {
            if (!TryParseBoolLiteral(boolLiteralContext, out var boolLiteral))
                return false;

            expression = boolLiteral;
        }
        else if (TryGet(context, context.IntLiteral, out var intLiteralContext))
        {
            if (!TryParseIntLiteral(intLiteralContext, out var intLiteral))
                return false;

            expression = intLiteral;
        }
        else if (TryGet(context, context.FloatLiteral, out var floatLiteralContext))
        {
            if (!TryParseFloatLiteral(floatLiteralContext, out var floatLiteral))
                return false;

            expression = floatLiteral;
        }
        else if (TryGet(context, context.StringLiteral, out var stringLiteralContext))
        {
            if (!TryParseStringLiteral(stringLiteralContext, out var stringLiteral))
                return false;

            expression = stringLiteral;
        }
        else
        {
            LogError(context, "Expected literal");
            return false;
        }

        return true;
    }

    private bool TryParseBoolLiteral(ITerminalNode node, out BoolLiteral literal)
    {
        literal = CreateAstNode<BoolLiteral>(node);

        if (!bool.TryParse(node.Symbol.Text, out bool value))
        {
            LogError(node.Symbol, "Invalid boolean value");
            return false;
        }

        literal.Value = value;

        return true;
    }

    private bool TryParseIntLiteral(ITerminalNode node, out IntLiteral literal)
    {
        literal = CreateAstNode<IntLiteral>(node);

        int value = 0;
        int sign = 1;
        string intString = node.Symbol.Text;
        if (intString.StartsWith("-"))
        {
            sign = -1;
            intString = intString.Substring(1);
        }
        else if (intString.StartsWith("+"))
        {
            sign = 1;
            intString = intString.Substring(1);
        }

        if (intString.StartsWith("0x", StringComparison.InvariantCultureIgnoreCase))
        {
            // hex number
            if (!int.TryParse(intString.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value))
            {
                LogError(node.Symbol, "Invalid hexidecimal integer value");
                return false;
            }
        }
        else
        {
            // assume decimal
            if (!int.TryParse(intString, out value))
            {
                LogError(node.Symbol, "Invalid decimal integer value");
                return false;
            }
        }

        literal.Value = value * sign;

        return true;
    }

    private bool TryParseFloatLiteral(ITerminalNode node, out FloatLiteral literal)
    {
        literal = CreateAstNode<FloatLiteral>(node);

        string floatString = node.Symbol.Text;
        if (floatString.EndsWith("f", StringComparison.InvariantCultureIgnoreCase))
        {
            floatString = floatString.Substring(0, floatString.Length - 1);
        }

        if (!float.TryParse(floatString, NumberStyles.Float, CultureInfo.InvariantCulture, out float value))
        {
            LogError(node.Symbol, "Invalid float value");
            return false;
        }

        literal.Value = value;

        return true;
    }

    private bool TryParseStringLiteral(ITerminalNode node, out StringLiteral literal)
    {
        literal = CreateAstNode<StringLiteral>(node);
        literal.Value = node.Symbol.Text.Trim('\"');

        return true;
    }

    //
    // Parameter list
    //
    private bool TryParseParameterList(FlowScriptParser.ParameterListContext context, out List<Parameter> parameters)
    {
        LogTrace("Parsing parameter list");
        LogContextInfo(context);

        parameters = new List<Parameter>();

        // Parse parameter list
        if (!TryGet(context, "Expected parameter list", context.parameter, out var parameterContexts))
            return false;

        foreach (var parameterContext in parameterContexts)
        {
            Parameter parameter = null;
            if (!TryFunc(parameterContext, "Failed to parse parameter", () => TryParseParameter(parameterContext, out parameter)))
                return false;

            parameters.Add(parameter);
        }

        return true;
    }

    private bool TryParseParameter(FlowScriptParser.ParameterContext context, out Parameter parameter)
    {
        LogContextInfo(context);

        var isArray = context.arraySignifier() != null;
        if (!isArray)
            parameter = CreateAstNode<Parameter>(context);
        else
            parameter = CreateAstNode<ArrayParameter>(context);

        if (context.Out() != null)
        {
            parameter.Modifier = ParameterModifier.Out;
        }

        // Parse type identifier
        if (!TryGet(context, "Expected function return type", () => context.TypeIdentifier(), out var typeIdentifierNode))
        {
            return false;
        }

        TypeIdentifier typeIdentifier = null;
        if (!TryFunc(typeIdentifierNode, "Failed to parse parameter type", () => TryParseTypeIdentifier(typeIdentifierNode, out typeIdentifier)))
            return false;

        parameter.Type = typeIdentifier;

        // Parse identifier
        if (!TryGet(context, "Expected parameter identifier", () => context.Identifier(), out var identifierNode))
            return false;

        Identifier identifier = null;
        if (!TryFunc(identifierNode, "Failed to parse parameter identifier", () => TryParseIdentifier(identifierNode, out identifier)))
            return false;

        parameter.Identifier = identifier;

        if (!isArray)
        {
            identifier.ExpressionValueKind = parameter.Type.ValueKind;
        }
        else
        {
            var sizeLiteral = context.arraySignifier().IntLiteral();
            if (!(sizeLiteral != null && TryParseIntLiteral(sizeLiteral, out var size)))
            {
                LogError(context, "Array parameter must have array size specified");
                return false;
            }

            ((ArrayParameter)parameter).Size = size;
        }

        LogTrace($"Parsed parameter: {parameter}");

        return true;
    }

    private bool TryParseArgument(FlowScriptParser.ArgumentContext context, out Argument argument)
    {
        LogContextInfo(context);

        argument = CreateAstNode<Argument>(context);

        if (context.expression() != null)
        {
            Expression expression = null;
            if (!TryFunc(context, "Failed to parse expression", () => TryParseExpression(context.expression(), out expression)))
                return false;

            argument.Expression = expression;
        }
        else
        {
            Identifier identifier = null;
            if (!TryFunc(context, "Failed to parse expression", () => TryParseIdentifier(context.Identifier(), out identifier)))
                return false;

            argument.Expression = identifier;
            if (context.Out() != null)
                argument.Modifier = ArgumentModifier.Out;
        }

        return true;
    }

    //
    // Identifiers
    //
    private bool TryParseTypeIdentifier(ITerminalNode node, out TypeIdentifier identifier)
    {
        identifier = CreateAstNode<TypeIdentifier>(node);
        identifier.Text = node.Symbol.Text;

        if (!System.Enum.TryParse<ValueKind>(identifier.Text, true, out var primitiveType))
        {
            primitiveType = ValueKind.Int;
            //LogError( node.Symbol, $"Unknown value type: {identifier.Value }" );
            //return false;
        }

        identifier.ValueKind = primitiveType;

        return true;
    }

    private bool TryParseIdentifier(ITerminalNode node, out Identifier identifier)
    {
        identifier = CreateAstNode<Identifier>(node);
        identifier.Text = node.Symbol.Text;
        if (identifier.Text.StartsWith("``"))
        {
            // verbatim identifier
            // ``foo``
            // 0123456
            identifier.Text = identifier.Text.Substring(2, identifier.Text.Length - 4);
        }

        return true;
    }


    //
    // If statement
    //
    private bool TryParseIfStatement(FlowScriptParser.IfStatementContext context, out IfStatement ifStatement)
    {
        LogContextInfo(context);

        ifStatement = CreateAstNode<IfStatement>(context);

        // Expression
        {
            if (!TryGet(context, "Expected if condition expression", context.expression, out var expressionNode))
                return false;

            Expression condition = null;
            if (!TryFunc(expressionNode, "Failed to parse if condition expression", () => TryParseExpression(expressionNode, out condition)))
                return false;

            ifStatement.Condition = condition;
        }

        LogTrace($"Parsing if statement: {ifStatement}");

        // Body
        {
            if (!TryGet(context, "Expected if body", () => context.statement(0), out var bodyContext))
                return false;

            Statement body = null;
            if (!TryFunc(bodyContext, "Failed to parse if body", () => TryParseStatement(bodyContext, out body)))
                return false;

            if (body is CompoundStatement)
            {
                ifStatement.Body = (CompoundStatement)body;
            }
            else
            {
                ifStatement.Body = CreateAstNode<CompoundStatement>(bodyContext);
                ifStatement.Body.Statements.Add(body);
            }
        }

        // Else statement
        {
            if (TryGet(context, () => context.statement(1), out var elseBodyContext))
            {
                Statement body = null;
                if (!TryFunc(elseBodyContext, "Failed to parse else body", () => TryParseStatement(elseBodyContext, out body)))
                    return false;

                if (body is CompoundStatement)
                {
                    ifStatement.ElseBody = (CompoundStatement)body;
                }
                else
                {
                    ifStatement.ElseBody = CreateAstNode<CompoundStatement>(elseBodyContext);
                    ifStatement.ElseBody.Statements.Add(body);
                }
            }
        }

        LogTrace($"Parsed if statement: {ifStatement}");

        return true;
    }

    //
    // For statement
    //
    private bool TryParseForStatement(FlowScriptParser.ForStatementContext context, out ForStatement forStatement)
    {
        LogContextInfo(context);

        forStatement = CreateAstNode<ForStatement>(context);

        if (!TryParseStatement(context.statement(0), out var initializer))
        {
            LogError(context.statement(0), "Failed to parse for statement initializer");
            return false;
        }

        forStatement.Initializer = initializer;

        if (!TryParseExpression(context.expression(0), out var condition))
        {
            LogError(context.statement(0), "Failed to parse for statement condition");
            return false;
        }

        forStatement.Condition = condition;

        if (!TryParseExpression(context.expression(1), out var afterLoop))
        {
            LogError(context.statement(0), "Failed to parse for statement after loop expression");
            return false;
        }

        forStatement.AfterLoop = afterLoop;

        LogTrace($"Parsing for loop: {forStatement}");

        if (!TryParseStatement(context.statement(1), out var body))
        {
            LogError(context.statement(0), "Failed to parse for statement body");
            return false;
        }

        if (body is CompoundStatement)
        {
            forStatement.Body = (CompoundStatement)body;
        }
        else
        {
            forStatement.Body = CreateAstNode<CompoundStatement>(context.statement(1));
            forStatement.Body.Statements.Add(body);
        }

        LogTrace($"Parsed for loop: {forStatement}");

        return true;
    }

    //
    // While statement
    //
    private bool TryParseWhileStatement(FlowScriptParser.WhileStatementContext context, out WhileStatement whileStatement)
    {
        LogContextInfo(context);

        whileStatement = CreateAstNode<WhileStatement>(context);

        if (!TryParseExpression(context.expression(), out var condition))
        {
            LogError(context.expression(), "Failed to parse while statement condition");
            return false;
        }

        whileStatement.Condition = condition;

        LogTrace($"Parsing while loop: {whileStatement}");

        if (!TryParseStatement(context.statement(), out var body))
        {
            LogError(context.statement(), "Failed to parse while statement body");
            return false;
        }

        if (body is CompoundStatement)
        {
            whileStatement.Body = (CompoundStatement)body;
        }
        else
        {
            whileStatement.Body = CreateAstNode<CompoundStatement>(context.statement());
            whileStatement.Body.Statements.Add(body);
        }

        LogTrace($"Parsed while loop: {whileStatement}");

        return true;
    }

    //
    // Goto statement
    //
    private bool TryParseGotoStatement(FlowScriptParser.GotoStatementContext context, out GotoStatement gotoStatement)
    {
        LogContextInfo(context);

        gotoStatement = CreateAstNode<GotoStatement>(context);

        if (context.Case() != null)
        {
            if (context.Default() == null)
            {
                if (!TryParseExpression(context.expression(), out var expression))
                {
                    LogError(context, "Failed to parse goto label identifier");
                    return false;
                }

                gotoStatement.Label = expression;
            }
            else
            {
                // TODO: fix this hack
                gotoStatement.Label = new NullExpression();
            }
        }
        else
        {
            if (!TryGet(context, context.Identifier, out var identifier))
            {
                LogError(context, "Expected goto label identifier");
                return false;
            }

            if (!TryParseIdentifier(identifier, out var target))
            {
                LogError(context, "Failed to parse goto label identifier");
                return false;
            }

            gotoStatement.Label = target;
        }


        LogTrace($"Parsed goto statement: {gotoStatement}");

        return true;
    }

    //
    // Return statement
    //
    private bool TryParseReturnStatement(FlowScriptParser.ReturnStatementContext context, out ReturnStatement returnStatement)
    {
        LogContextInfo(context);

        returnStatement = CreateAstNode<ReturnStatement>(context);

        if (TryGet(context, context.expression, out var expressionContext))
        {
            if (!TryParseExpression(expressionContext, out var expression))
            {
                LogError(expressionContext, "Failed to parse return statement expression");
                return false;
            }

            returnStatement.Value = expression;
        }

        LogTrace($"Parsed return statement: {returnStatement}");

        return true;
    }

    private bool TryParseSwitchStatement(FlowScriptParser.SwitchStatementContext context, out SwitchStatement switchStatement)
    {
        LogContextInfo(context);

        switchStatement = CreateAstNode<SwitchStatement>(context);

        // Parse switch-on expression
        if (!TryParseExpression(context.expression(), out var switchOn))
        {
            LogError(context.expression(), "Failed to parse switch statement 'switch-on' expression");
            return false;
        }

        switchStatement.SwitchOn = switchOn;

        LogTrace($"Parsing switch statement: {switchStatement}");

        // Parse switch labels
        foreach (var switchLabelContext in context.switchLabel())
        {
            FlowScriptSwitchLabel label = null;

            if (switchLabelContext.Case() != null)
            {
                // Parse expression
                if (!TryParseExpression(switchLabelContext.expression(), out var condition))
                {
                    LogError(context.expression(), "Failed to parse switch statement label expression");
                    return false;
                }

                var conditionLabel = CreateAstNode<ConditionSwitchLabel>(switchLabelContext);
                conditionLabel.Condition = condition;

                label = conditionLabel;
            }
            else
            {
                label = CreateAstNode<DefaultSwitchLabel>(switchLabelContext);
            }

            // Parse statements
            if (!TryParseStatements(switchLabelContext.statement(), out var body))
            {
                mLogger.Error("Failed to parse switch statement label body");
                return false;
            }

            label.Body = body;
            switchStatement.Labels.Add(label);
        }

        LogTrace($"Done parsing switch statement: {switchStatement}");

        return true;
    }

    //
    // Parse helpers
    //
    private T CreateAstNode<T>(ParserRuleContext context) where T : SyntaxNode, new()
    {
        T instance = new T { SourceInfo = ParseSourceInfo(context.Start) };

        return instance;
    }

    private T CreateAstNode<T>(ITerminalNode node) where T : SyntaxNode, new()
    {
        T instance = new T { SourceInfo = ParseSourceInfo(node.Symbol) };

        return instance;
    }

    private SourceInfo ParseSourceInfo(IToken token)
    {
        return new SourceInfo(token.Line, token.Column, token.TokenSource.SourceName);
    }

    //
    // Predicates
    //
    private bool TryFunc(ParserRuleContext context, string errorText, Func<bool> func)
    {
        if (!func())
        {
            LogError(context, errorText);
            return false;
        }

        return true;
    }

    private bool TryFunc(ITerminalNode node, string errorText, Func<bool> func)
    {
        if (!func())
        {
            LogError(node.Symbol, errorText);
            return false;
        }

        return true;
    }

    private bool TryGet<T>(ParserRuleContext context, string errorText, Func<T> getFunc, out T value)
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

        return value != null;
    }

    private bool TryCast<T>(object obj, out T value) where T : class
    {
        value = obj as T;
        return value != null;
    }

    //
    // Logging
    //
    private void LogContextInfo(ParserRuleContext context)
    {
        LogTrace($"({context.Start.Line:D4}:{context.Start.Column:D4}) Entered parsing context {context.GetType().Name} rule: {FlowScriptParser.ruleNames[context.RuleIndex]}");
    }

    private void LogError(ParserRuleContext context, string str)
    {
        mLogger.Error($"({context.Start.Line:D4}:{context.Start.Column:D4}) {str}");

        if (Debugger.IsAttached)
            Debugger.Break();
    }

    private void LogError(IToken token, string message)
    {
        mLogger.Error($"({token.Line:D4}:{token.Column:D4}) {message}");

        if (Debugger.IsAttached)
            Debugger.Break();
    }

    private void LogWarning(ParserRuleContext context, string str)
    {
        mLogger.Warning($"({context.Start.Line:D4}:{context.Start.Column:D4}) {str}");
    }

    private void LogInfo(string message)
    {
        mLogger.Info($"{message}");
    }

    private void LogTrace(string message)
    {
        mLogger.Trace($"{message}");
    }

    /// <summary>
    /// Antlr error listener for catching syntax errors while parsing.
    /// </summary>
    private class AntlrErrorListener : IAntlrErrorListener<IToken>
    {
        private Logger mLogger;

        public AntlrErrorListener(Logger logger)
        {
            mLogger = logger;
        }

        public void SyntaxError(IRecognizer recognizer, IToken offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
        {
            mLogger.Error($"Syntax error: {msg} ({offendingSymbol.Line}:{offendingSymbol.Column})");
        }
    }
}
