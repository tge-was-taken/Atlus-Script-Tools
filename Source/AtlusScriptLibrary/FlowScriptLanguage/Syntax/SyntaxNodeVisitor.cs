namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax;

public abstract class SyntaxNodeVisitor
{

    public virtual void Visit(CompilationUnit compilationUnit)
    {
        foreach (var import in compilationUnit.Imports)
        {
            Visit(import);
        }

        foreach (var statement in compilationUnit.Declarations)
        {
            Visit(statement);
        }
    }

    public virtual void Visit(Import import)
    {
    }

    public virtual void Visit(Parameter parameter)
    {
        Visit(parameter.Type);
        Visit(parameter.Identifier);
    }

    public virtual void Visit(Statement statement)
    {
        DispatchVisit(statement);
    }

    public virtual void Visit(Comment comment)
    {

    }

    public virtual void Visit(SyntaxNode syntaxNode)
    {
        DispatchVisit(syntaxNode);
    }

    public virtual void Visit(VariableModifier variableModifier)
    {
    }

    public virtual void Visit(BreakStatement breakStatement)
    {
    }

    public virtual void Visit(CompoundStatement compoundStatement)
    {
        foreach (var statement in compoundStatement)
        {
            Visit(statement);
        }
    }

    public virtual void Visit(ContinueStatement continueStatement)
    {
    }

    public virtual void Visit(Declaration declaration)
    {
        DispatchVisit(declaration);
    }

    public virtual void Visit(Expression expression)
    {

        DispatchVisit(expression);
    }

    public virtual void Visit(ForStatement forStatement)
    {
        DispatchVisit(forStatement.Condition);
        DispatchVisit(forStatement.AfterLoop);
        if (forStatement.Body != null)
            Visit(forStatement.Body);
    }

    public virtual void Visit(GotoStatement gotoStatement)
    {
        Visit(gotoStatement.Label);
    }

    public virtual void Visit(IfStatement ifStatement)
    {
        DispatchVisit(ifStatement.Condition);

        if (ifStatement.Body != null)
            Visit(ifStatement.Body);

        if (ifStatement.ElseBody != null)
            Visit(ifStatement.ElseBody);
    }

    public virtual void Visit(NullStatement nullStatement)
    {
    }

    public virtual void Visit(ReturnStatement returnStatement)
    {
        if (returnStatement.Value != null)
        {
            DispatchVisit(returnStatement.Value);
        }
    }

    public virtual void Visit(SwitchStatement switchStatement)
    {
        DispatchVisit(switchStatement.SwitchOn);
        foreach (var label in switchStatement.Labels)
        {
            DispatchVisit(label);
        }
    }

    public virtual void Visit(WhileStatement whileStatement)
    {
        DispatchVisit(whileStatement.Condition);
        Visit(whileStatement.Body);
    }

    public virtual void Visit(FunctionDeclaration functionDeclaration)
    {
        Visit(functionDeclaration.Index);
        Visit(functionDeclaration.ReturnType);
        Visit(functionDeclaration.Identifier);
        foreach (var parameter in functionDeclaration.Parameters)
        {
            Visit(parameter);
        }
    }

    public virtual void Visit(LabelDeclaration labelDeclaration)
    {
        Visit(labelDeclaration.Identifier);
    }

    public virtual void Visit(ProcedureDeclaration procedureDeclaration)
    {
        Visit(procedureDeclaration.ReturnType);
        Visit(procedureDeclaration.Identifier);
        foreach (var parameter in procedureDeclaration.Parameters)
        {
            Visit(parameter);
        }
        Visit(procedureDeclaration.Body);
    }

    public virtual void Visit(VariableDeclaration variableDeclaration)
    {
        Visit(variableDeclaration.Modifier);
        Visit(variableDeclaration.Type);
        Visit(variableDeclaration.Identifier);
        if (variableDeclaration.Initializer != null)
        {
            Visit(variableDeclaration.Initializer);
        }
    }

    public virtual void Visit(BinaryExpression binaryExpression)
    {
        DispatchVisit(binaryExpression);
    }

    public virtual void Visit(CallOperator callOperator)
    {
        Visit(callOperator.Identifier);
        foreach (var argument in callOperator.Arguments)
        {
            Visit(argument);
        }
    }

    public virtual void Visit(Argument argument)
    {
        Visit(argument.Expression);
    }

    public virtual void Visit(Identifier identifier)
    {
        if (identifier is TypeIdentifier)
        {
            Visit((TypeIdentifier)identifier);
        }
    }

    public virtual void Visit(UnaryExpression unaryExpression)
    {
        DispatchVisit(unaryExpression);
    }

    public virtual void Visit(AdditionOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(AssignmentOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(DivisionOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(EqualityOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(GreaterThanOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(GreaterThanOrEqualOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(LessThanOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(LessThanOrEqualOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(LogicalAndOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(LogicalOrOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(MultiplicationOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(NonEqualityOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(SubtractionOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(AdditionAssignmentOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(AssignmentOperatorBase binaryOperator)
    {
        DispatchVisit(binaryOperator);
    }

    public virtual void Visit(CompoundAssignmentOperator binaryOperator)
    {
        DispatchVisit(binaryOperator);
    }

    public virtual void Visit(DivisionAssignmentOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(MultiplicationAssignmentOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(SubtractionAssignmentOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(TypeIdentifier typeIdentifier)
    {
    }

    public virtual void Visit(BoolLiteral literal)
    {
    }

    public virtual void Visit(FloatLiteral literal)
    {
    }

    public virtual void Visit(IntLiteral literal)
    {
    }

    public virtual void Visit(UIntLiteral literal)
    {
    }

    public virtual void Visit(StringLiteral literal)
    {
    }

    public virtual void Visit(LogicalNotOperator unaryOperator)
    {
        Visit(unaryOperator.Operand);
    }

    public virtual void Visit(NegationOperator unaryOperator)
    {
        Visit(unaryOperator.Operand);
    }

    public virtual void Visit(PostfixDecrementOperator unaryOperator)
    {
        Visit(unaryOperator.Operand);
    }

    public virtual void Visit(PostfixIncrementOperator unaryOperator)
    {
        Visit(unaryOperator.Operand);
    }

    public virtual void Visit(PostfixOperator unaryOperator)
    {
        DispatchVisit(unaryOperator);
    }

    public virtual void Visit(PrefixDecrementOperator unaryOperator)
    {
        Visit(unaryOperator.Operand);
    }

    public virtual void Visit(PrefixIncrementOperator unaryOperator)
    {
        Visit(unaryOperator.Operand);
    }

    public virtual void Visit(PrefixOperator prefixOperator)
    {
        DispatchVisit(prefixOperator);
    }

    public virtual void Visit(EnumDeclaration enumDeclaration)
    {
        Visit(enumDeclaration.Identifier);

        foreach (var enumValueDeclaration in enumDeclaration.Values)
        {
            Visit(enumValueDeclaration);
        }
    }

    public virtual void Visit(EnumValueDeclaration enumValueDeclaration)
    {
        Visit(enumValueDeclaration.Identifier);
        Visit(enumValueDeclaration.Value);
    }

    public virtual void Visit(MemberAccessExpression memberAccessExpression)
    {
        Visit(memberAccessExpression.Operand);
        Visit(memberAccessExpression.Member);
    }

    public virtual void Visit(FlowScriptSwitchLabel switchLabel)
    {
        DispatchVisit(switchLabel);
    }

    public virtual void Visit(ConditionSwitchLabel switchLabel)
    {
        Visit(switchLabel.Condition);
        foreach (var statement in switchLabel.Body)
        {
            Visit(statement);
        }
    }

    public virtual void Visit(DefaultSwitchLabel switchLabel)
    {
        foreach (var statement in switchLabel.Body)
        {
            Visit(statement);
        }
    }

    public virtual void Visit(ModulusOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(ModulusAssignmentOperator binaryOperator)
    {
        Visit(binaryOperator.Left);
        Visit(binaryOperator.Right);
    }

    public virtual void Visit(InitializerList initializerList)
    {
        foreach (var expression in initializerList.Expressions)
        {
            Visit(expression);
        }
    }

    public virtual void Visit(NullExpression nullExpression)
    {
    }

    public virtual void Visit(SubscriptOperator subscriptOperator)
    {
        Visit(subscriptOperator.Operand);
        Visit(subscriptOperator.Index);
    }

    /// <summary>
    /// Dispatches to the most derived <see cref="Visit"/> overload for the node's runtime type.
    /// Replaces runtime overload resolution via <c>dynamic</c>, which Native AOT cannot support.
    /// </summary>
    public void DispatchVisit(SyntaxNode node)
    {
        switch (node)
        {
            case null: return;

            // Statements
            case BreakStatement n: Visit(n); return;
            case CompoundStatement n: Visit(n); return;
            case Comment n: Visit(n); return;
            case ContinueStatement n: Visit(n); return;
            case ForStatement n: Visit(n); return;
            case GotoStatement n: Visit(n); return;
            case IfStatement n: Visit(n); return;
            case NullStatement n: Visit(n); return;
            case ReturnStatement n: Visit(n); return;
            case SwitchStatement n: Visit(n); return;
            case WhileStatement n: Visit(n); return;

            // Declarations
            case VariableDeclaration n: Visit(n); return;
            case EnumDeclaration n: Visit(n); return;
            case EnumValueDeclaration n: Visit(n); return;
            case FunctionDeclaration n: Visit(n); return;
            case LabelDeclaration n: Visit(n); return;
            case ProcedureDeclaration n: Visit(n); return;

            // Binary operators
            case AdditionOperator n: Visit(n); return;
            case SubtractionOperator n: Visit(n); return;
            case MultiplicationOperator n: Visit(n); return;
            case DivisionOperator n: Visit(n); return;
            case ModulusOperator n: Visit(n); return;
            case EqualityOperator n: Visit(n); return;
            case NonEqualityOperator n: Visit(n); return;
            case GreaterThanOperator n: Visit(n); return;
            case GreaterThanOrEqualOperator n: Visit(n); return;
            case LessThanOperator n: Visit(n); return;
            case LessThanOrEqualOperator n: Visit(n); return;
            case LogicalAndOperator n: Visit(n); return;
            case LogicalOrOperator n: Visit(n); return;

            // Assignment operators
            case AssignmentOperator n: Visit(n); return;
            case AdditionAssignmentOperator n: Visit(n); return;
            case SubtractionAssignmentOperator n: Visit(n); return;
            case MultiplicationAssignmentOperator n: Visit(n); return;
            case DivisionAssignmentOperator n: Visit(n); return;
            case ModulusAssignmentOperator n: Visit(n); return;

            // Unary operators
            case LogicalNotOperator n: Visit(n); return;
            case NegationOperator n: Visit(n); return;
            case PostfixDecrementOperator n: Visit(n); return;
            case PostfixIncrementOperator n: Visit(n); return;
            case PrefixDecrementOperator n: Visit(n); return;
            case PrefixIncrementOperator n: Visit(n); return;

            // Literals
            case BoolLiteral n: Visit(n); return;
            case FloatLiteral n: Visit(n); return;
            case IntLiteral n: Visit(n); return;
            case UIntLiteral n: Visit(n); return;
            case StringLiteral n: Visit(n); return;

            // Other expressions
            case CallOperator n: Visit(n); return;
            case MemberAccessExpression n: Visit(n); return;
            case SubscriptOperator n: Visit(n); return;
            case InitializerList n: Visit(n); return;
            case NullExpression n: Visit(n); return;
            case TypeIdentifier n: Visit(n); return;
            case Identifier n: Visit(n); return;

            // Switch labels
            case ConditionSwitchLabel n: Visit(n); return;
            case DefaultSwitchLabel n: Visit(n); return;

            // Structural nodes
            case CompilationUnit n: Visit(n); return;
            case Import n: Visit(n); return;
            case Argument n: Visit(n); return;
            case Parameter n: Visit(n); return;
            case VariableModifier n: Visit(n); return;

            default:
                throw new System.NotSupportedException(
                    $"No {nameof(SyntaxNodeVisitor)}.{nameof(Visit)} overload for node type '{node.GetType()}'");
        }
    }
}
