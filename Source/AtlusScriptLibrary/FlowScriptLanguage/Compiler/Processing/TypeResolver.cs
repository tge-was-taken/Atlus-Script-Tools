using AtlusScriptLibrary.Common.Logging;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;
using System.Collections.Generic;
using System.Diagnostics;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler.Processing;

public class TypeResolver
{
    private Logger mLogger;
    private Stack<DeclarationScope> mScopes;
    private DeclarationScope mRootScope;

    private DeclarationScope Scope => mScopes.Peek();

    /// <summary>
    /// Initializes a FlowScript type resolver with a default configuration.
    /// </summary>
    public TypeResolver()
    {
        mLogger = new Logger(nameof(TypeResolver));
        mScopes = new Stack<DeclarationScope>();
    }

    /// <summary>
    /// Adds a resolver log listener. Use this if you want to see what went wrong during resolving.
    /// </summary>
    /// <param name="listener">The listener to add.</param>
    public void AddListener(LogListener listener)
    {
        listener.Subscribe(mLogger);
    }

    /// <summary>
    /// Try to resolve expression types in the given compilation unit.
    /// </summary>
    /// <param name="compilationUnit"></param>
    /// <returns></returns>
    public bool TryResolveTypes(CompilationUnit compilationUnit)
    {
        LogTrace($"{nameof(TryResolveTypes)}( {nameof(compilationUnit)} = {compilationUnit})");
        LogInfo("Resolving types in compilation unit");

        if (!TryResolveTypesInCompilationUnit(compilationUnit))
            return false;

        LogInfo("Done resolving types in compilation unit");

        return true;
    }

    //
    // Registering declarations
    //
    private bool TryRegisterTopLevelDeclarations(CompilationUnit compilationUnit)
    {
        LogTrace("Registering/forward-declaring top level declarations");

        if (!TryRegisterDeclarations(compilationUnit.Declarations))
            return false;

        return true;
    }

    private bool TryRegisterDeclarations(IEnumerable<Statement> statements)
    {
        foreach (var statement in statements)
        {
            if (statement is Declaration declaration)
            {
                if (!TryRegisterDeclaration(declaration))
                    return false;
            }
        }

        return true;
    }

    private bool TryRegisterDeclaration(Declaration declaration)
    {
        LogTrace($"{nameof(TryRegisterDeclaration)}( declaration = {declaration})");

        if (!Scope.TryRegisterDeclaration(declaration))
        {
            // Special case: forward declared declarations on top level
            if (Scope.Parent != null)
            {
                Scope.TryGetDeclaration(declaration.Identifier, out var existingDeclaration);
                LogError($"Identifier {declaration.Identifier} already defined as: {existingDeclaration}");
                return false;
            }
        }

        return true;
    }

    //
    // Type resolving
    //
    private bool TryResolveTypesInCompilationUnit(CompilationUnit compilationUnit)
    {
        LogTrace($"{nameof(TryResolveTypesInCompilationUnit)}( compilationUnit = {compilationUnit})");

        // Enter compilation unit scope
        PushScope();

        // Top level declarations are handled seperately to make them accessible throughout the entire file
        // regardless of scope
        if (!TryRegisterTopLevelDeclarations(compilationUnit))
            return false;

        foreach (var statement in compilationUnit.Declarations)
        {
            if (!TryResolveTypesInStatement(statement))
                return false;
        }

        // Exit compilation unit scope
        PopScope();

        return true;
    }

    // Statements
    private bool TryResolveTypesInStatement(Statement statement)
    {
        LogTrace($"{nameof(TryResolveTypesInStatement)}( statement = {statement})");

        if (statement is CompoundStatement compoundStatement)
        {
            if (!TryResolveTypesInCompoundStatement(compoundStatement))
                return false;
        }
        else if (statement is Declaration declaration)
        {
            if (!TryRegisterDeclaration(declaration))
                return false;

            if (!TryResolveTypesInDeclaration(declaration))
                return false;
        }
        else if (statement is Expression expression)
        {
            if (!TryResolveTypesInExpression(expression))
                return false;
        }
        else if (statement is IfStatement ifStatement)
        {
            if (!TryResolveTypesInIfStatement(ifStatement))
                return false;
        }
        else if (statement is ForStatement forStatement)
        {
            if (!TryResolveTypesInForStatement(forStatement))
                return false;
        }
        else if (statement is WhileStatement whileStatement)
        {
            if (!TryResolveTypesInWhileStatement(whileStatement))
                return false;
        }
        else if (statement is ReturnStatement returnStatement)
        {
            if (returnStatement.Value != null)
            {
                if (!TryResolveTypesInExpression(returnStatement.Value))
                    return false;
            }
        }
        else if (statement is GotoStatement gotoStatement)
        {
            gotoStatement.Label.ExpressionValueKind = ValueKind.Label;
        }
        else if (statement is SwitchStatement switchStatement)
        {
            if (!TryResolveTypesInSwitchStatement(switchStatement))
                return false;
        }
        else if (statement is BreakStatement)
        {
            // Not an expression
        }
        else
        {
            LogWarning($"No types resolved in statement '{statement}'");
            //return false;
        }

        return true;
    }

    private bool TryResolveTypesInCompoundStatement(CompoundStatement compoundStatement)
    {
        LogTrace($"{nameof(TryResolveTypesInCompoundStatement)}( statement = {compoundStatement})");

        PushScope();

        foreach (var statement in compoundStatement)
        {
            if (!TryResolveTypesInStatement(statement))
                return false;
        }

        PopScope();

        return true;
    }

    private bool TryResolveTypesInDeclaration(Declaration declaration)
    {
        LogTrace($"{nameof(TryResolveTypesInDeclaration)}( declaration = {declaration})");

        if (declaration.DeclarationType != DeclarationType.Label)
        {
            if (!TryResolveTypesInIdentifier(declaration.Identifier))
            {
                LogError(declaration.Identifier, $"Failed to resolve types in declaration identifier: {declaration.Identifier}");
                return false;
            }
        }
        else
        {
            declaration.Identifier.ExpressionValueKind = ValueKind.Label;
        }

        if (declaration is ProcedureDeclaration procedureDeclaration)
        {
            if (!TryResolveTypesInProcedureDeclaration(procedureDeclaration))
            {
                LogError(procedureDeclaration, $"Failed to resolve types in procedure declaration: {procedureDeclaration}");
                return false;
            }
        }
        else if (declaration is VariableDeclaration variableDeclaration)
        {
            if (!TryResolveTypesInVariableDeclaration(variableDeclaration))
            {
                LogError(variableDeclaration, $"Failed to resolve types in variable declaration: {variableDeclaration}");
                return false;
            }
        }

        return true;
    }

    internal bool TryResolveTypesInExpression(Expression expression)
    {
        LogTrace($"{nameof(TryResolveTypesInExpression)}( expression = {expression})");

        if (expression is InitializerList initializerList)
        {
            foreach (var expr in initializerList.Expressions)
            {
                if (!TryResolveTypesInExpression(expr))
                    return false;
            }
        }
        else if (expression is SubscriptOperator subscriptOperator)
        {
            expression.ExpressionValueKind = subscriptOperator.Operand.ExpressionValueKind;
            if (!TryResolveTypesInExpression(subscriptOperator.Index))
                return false;
        }
        else if (expression is MemberAccessExpression)
        {
            expression.ExpressionValueKind = ValueKind.Int; // enum
        }
        else if (expression is CallOperator callExpression)
        {
            if (!TryResolveTypesInCallExpression(callExpression))
                return false;
        }
        else if (expression is UnaryExpression unaryExpression)
        {
            if (!TryResolveTypesInExpression(unaryExpression.Operand))
                return false;

            unaryExpression.ExpressionValueKind = unaryExpression.Operand.ExpressionValueKind;
        }
        else if (expression is BinaryExpression binaryExpression)
        {
            if (!TryResolveTypesInExpression(binaryExpression.Left))
                return false;

            if (!TryResolveTypesInExpression(binaryExpression.Right))
                return false;

            if (!(expression is EqualityOperator || expression is NonEqualityOperator ||
                 expression is GreaterThanOperator || expression is GreaterThanOrEqualOperator ||
                 expression is LessThanOperator || expression is LessThanOrEqualOperator ||
                 expression is LogicalAndOperator || expression is LogicalOrOperator))
            {
                binaryExpression.ExpressionValueKind = binaryExpression.Left.ExpressionValueKind;
            }
        }
        else if (expression is Identifier identifier)
        {
            if (!TryResolveTypesInIdentifier(identifier))
                return false;
        }
        else
        {
            if (expression.ExpressionValueKind == ValueKind.Unresolved)
            {
                LogError(expression, $"Unresolved expression: {expression}");
                return false;
            }
        }

        LogTrace(expression, $"Resolved expression {expression} to type {expression.ExpressionValueKind}");

        return true;
    }

    private bool TryResolveTypesInIfStatement(IfStatement ifStatement)
    {
        LogTrace($"{nameof(TryResolveTypesInIfStatement)}( ifStatement = {ifStatement})");

        if (!TryResolveTypesInExpression(ifStatement.Condition))
            return false;

        if (!TryResolveTypesInCompoundStatement(ifStatement.Body))
            return false;

        if (ifStatement.ElseBody != null)
        {
            if (!TryResolveTypesInCompoundStatement(ifStatement.ElseBody))
                return false;
        }

        return true;
    }

    private bool TryResolveTypesInForStatement(ForStatement forStatement)
    {
        LogTrace($"{nameof(TryResolveTypesInForStatement)}( forStatement = {forStatement})");

        // Enter for scope
        PushScope();

        // For loop Initializer
        if (!TryResolveTypesInStatement(forStatement.Initializer))
            return false;

        // For loop Condition
        if (!TryResolveTypesInExpression(forStatement.Condition))
            return false;

        // For loop After loop expression
        if (!TryResolveTypesInExpression(forStatement.AfterLoop))
            return false;

        // For loop Body
        if (!TryResolveTypesInCompoundStatement(forStatement.Body))
            return false;

        // Exit for scope
        PopScope();

        return true;
    }

    private bool TryResolveTypesInWhileStatement(WhileStatement whileStatement)
    {
        LogTrace($"{nameof(TryResolveTypesInWhileStatement)}( whileStatement = {whileStatement})");

        // Resolve types in while statement condition
        if (!TryResolveTypesInExpression(whileStatement.Condition))
            return false;

        // Resolve types in body
        if (!TryResolveTypesInCompoundStatement(whileStatement.Body))
            return false;

        return true;
    }

    private bool TryResolveTypesInSwitchStatement(SwitchStatement switchStatement)
    {
        LogTrace($"{nameof(TryResolveTypesInSwitchStatement)}( switchStatement = {switchStatement})");

        if (!TryResolveTypesInExpression(switchStatement.SwitchOn))
            return false;

        foreach (var label in switchStatement.Labels)
        {
            if (label is ConditionSwitchLabel conditionLabel)
            {
                if (!TryResolveTypesInExpression(conditionLabel.Condition))
                    return false;
            }

            foreach (var statement in label.Body)
            {
                if (!TryResolveTypesInStatement(statement))
                    return false;
            }
        }

        return true;
    }

    // Declarations
    private bool TryResolveTypesInProcedureDeclaration(ProcedureDeclaration declaration)
    {
        LogTrace($"{nameof(TryResolveTypesInProcedureDeclaration)}( {nameof(declaration)} = {declaration})");
        LogInfo(declaration, $"Resolving types in procedure '{declaration.Identifier.Text}'");

        // Nothing to resolve if there's no body
        if (declaration.Body == null)
            return true;

        // Enter procedure body scope
        PushScope();

        foreach (var parameter in declaration.Parameters)
        {
            var parameterDeclaration = new VariableDeclaration(
                new VariableModifier(VariableModifierKind.Local),
                parameter.Type,
                parameter.Identifier,
                null);

            if (!TryRegisterDeclaration(parameterDeclaration))
            {
                LogError(parameter, "Failed to register declaration for procedure parameter");
                return false;
            }
        }

        if (!TryResolveTypesInCompoundStatement(declaration.Body))
            return false;

        // Exit procedure body scope
        PopScope();

        return true;
    }

    private bool TryResolveTypesInVariableDeclaration(VariableDeclaration declaration)
    {
        LogTrace($"{nameof(TryResolveTypesInVariableDeclaration)}( {nameof(declaration)} = {declaration})");

        // Nothing to resolve if there's no initializer
        if (declaration.Initializer == null)
            return true;

        if (!TryResolveTypesInExpression(declaration.Initializer))
        {
            LogError(declaration.Initializer, $"Failed to resolve types in variable initializer expression: {declaration.Initializer}");
            return false;
        }

        //if ( declaration.IsArray && declaration.Initializer is InitializerList initializerList )
        //{
        //    initializerList.ExpressionValueKind = ValueKind.Array;
        //}

        return true;
    }

    // Expressions

    private bool TryResolveTypesInCallExpression(CallOperator callExpression)
    {
        LogTrace($"{nameof(TryResolveTypesInCallExpression)}( {nameof(callExpression)} = {callExpression})");

        if (!Scope.TryGetDeclaration(callExpression.Identifier, out var declaration))
        {
            // Disable for now because we import functions at compile time
            //LogWarning( callExpression, $"Call expression references undeclared identifier '{callExpression.Identifier.Value}'" );
        }

        if (declaration is FunctionDeclaration functionDeclaration)
        {
            callExpression.ExpressionValueKind = functionDeclaration.ReturnType.ValueKind;
            callExpression.Identifier.ExpressionValueKind = ValueKind.Function;
        }
        else if (declaration is ProcedureDeclaration procedureDeclaration)
        {
            callExpression.ExpressionValueKind = procedureDeclaration.ReturnType.ValueKind;
            callExpression.Identifier.ExpressionValueKind = ValueKind.Procedure;
        }

        foreach (var arg in callExpression.Arguments)
        {
            if (!TryResolveTypesInExpression(arg.Expression))
                return false;
        }

        return true;
    }

    private bool TryResolveTypesInIdentifier(Identifier identifier)
    {
        LogTrace($"{nameof(TryResolveTypesInIdentifier)}( {nameof(identifier)} = {identifier})");

        bool isUndeclared = false;
        if (!Scope.TryGetDeclaration(identifier, out var declaration))
        {
            LogInfo(identifier, $"Identifiers references undeclared identifier '{identifier.Text}'. Is this a compile time variable?");
            isUndeclared = true;
        }

        if (declaration is FunctionDeclaration)
        {
            identifier.ExpressionValueKind = ValueKind.Function;
        }
        else if (declaration is ProcedureDeclaration)
        {
            identifier.ExpressionValueKind = ValueKind.Procedure;
        }
        else if (declaration is VariableDeclaration variableDeclaration)
        {
            identifier.ExpressionValueKind = variableDeclaration.Type.ValueKind;
        }
        else if (declaration is LabelDeclaration)
        {
            identifier.ExpressionValueKind = ValueKind.Label;
        }
        else if (declaration is EnumDeclaration)
        {
            identifier.ExpressionValueKind = ValueKind.Void;
        }
        else if (!isUndeclared)
        {
            LogWarning(identifier, "Expected function, procedure, variable or label identifier");
        }

        return true;
    }

    //
    // Scope
    //
    private void PushScope()
    {
        if (mScopes.Count != 0)
        {
            mScopes.Push(new DeclarationScope(Scope));
        }
        else
        {
            mRootScope = new DeclarationScope(null);
            mScopes.Push(mRootScope);
        }
    }

    private void PopScope()
    {
        mScopes.Pop();
    }

    //
    // Logging
    //
    private void LogTrace(SyntaxNode node, string message)
    {
        if (node.SourceInfo != null)
            LogTrace($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
        else
            LogTrace(message);
    }

    private void LogTrace(string message)
    {
        mLogger.Trace($"{message}");
    }

    private void LogInfo(string message)
    {
        mLogger.Info($"{message}");
    }

    private void LogInfo(SyntaxNode node, string message)
    {
        mLogger.Info($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
    }

    private void LogError(SyntaxNode node, string message)
    {
        if (node.SourceInfo != null)
            LogError($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
        else
            LogError(message);

        if (Debugger.IsAttached)
            Debugger.Break();
    }

    private void LogError(string message)
    {
        mLogger.Error($"{message}");
    }

    private void LogWarning(string message)
    {
        mLogger.Warning($"{message}");
    }

    private void LogWarning(SyntaxNode node, string message)
    {
        mLogger.Warning($"({node.SourceInfo.Line:D4}:{node.SourceInfo.Column:D4}) {message}");
    }
}
