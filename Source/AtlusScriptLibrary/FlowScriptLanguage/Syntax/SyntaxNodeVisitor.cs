namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public abstract class SyntaxNodeVisitor
    {

        public virtual void Visit( CompilationUnit compilationUnit )
        {
            foreach ( var import in compilationUnit.Imports )
            {
                Visit( import );
            }

            foreach ( var statement in compilationUnit.Declarations )
            {
                Visit( statement );
            }
        }

        public virtual void Visit( Import import )
        {
        }

        public virtual void Visit( Parameter parameter )
        {
            Visit( parameter.Type );
            Visit( parameter.Identifier );
        }

        public virtual void Visit( Statement statement )
        {
            Visit( ( dynamic )statement );
        }

        public virtual void Visit( SyntaxNode syntaxNode )
        {
            Visit( ( dynamic )syntaxNode );
        }

        public virtual void Visit( VariableModifier variableModifier )
        {
        }

        public virtual void Visit( BreakStatement breakStatement )
        {
        }

        public virtual void Visit( CompoundStatement compoundStatement )
        {
            foreach ( var statement in compoundStatement )
            {
                Visit( statement );
            }
        }

        public virtual void Visit( ContinueStatement continueStatement )
        {
        }

        public virtual void Visit( Declaration declaration )
        {
            Visit( ( dynamic )declaration );
        }

        public virtual void Visit( Expression expression )
        {
            Visit( ( dynamic )expression );
        }

        public virtual void Visit( ForStatement forStatement )
        {
            Visit( (dynamic)forStatement.Condition );
            Visit( (dynamic)forStatement.AfterLoop );
            if ( forStatement.Body != null )
                Visit( forStatement.Body );
        }

        public virtual void Visit( GotoStatement gotoStatement )
        {
            Visit( gotoStatement.Label );
        }

        public virtual void Visit( IfStatement ifStatement )
        {
            Visit( (dynamic)ifStatement.Condition );

            if ( ifStatement.Body != null )
                Visit( ifStatement.Body );

            if ( ifStatement.ElseBody != null )
                Visit( ifStatement.ElseBody );
        }

        public virtual void Visit( NullStatement nullStatement )
        {
        }

        public virtual void Visit( ReturnStatement returnStatement )
        {
            if ( returnStatement.Value != null )
            {
                Visit( (dynamic)returnStatement.Value );
            }
        }

        public virtual void Visit( SwitchStatement switchStatement )
        {
            Visit( (dynamic)switchStatement.SwitchOn );
            foreach ( var label in switchStatement.Labels )
            {
                Visit( ( dynamic )label );
            }
        }

        public virtual void Visit( WhileStatement whileStatement )
        {
            Visit( ( dynamic )whileStatement.Condition );
            Visit( whileStatement.Body );
        }

        public virtual void Visit( FunctionDeclaration functionDeclaration )
        {
            Visit( functionDeclaration.Index );
            Visit( functionDeclaration.ReturnType );
            Visit( functionDeclaration.Identifier );
            foreach ( var parameter in functionDeclaration.Parameters )
            {
                Visit( parameter );
            }     
        }

        public virtual void Visit( LabelDeclaration labelDeclaration )
        {
            Visit( labelDeclaration.Identifier );
        }

        public virtual void Visit( ProcedureDeclaration procedureDeclaration )
        {
            Visit( procedureDeclaration.ReturnType );
            Visit( procedureDeclaration.Identifier );
            foreach ( var parameter in procedureDeclaration.Parameters )
            {
                Visit( parameter );
            }
            Visit( procedureDeclaration.Body );
        }

        public virtual void Visit( VariableDeclaration variableDeclaration )
        {
            Visit( variableDeclaration.Modifier );
            Visit( variableDeclaration.Type );
            Visit( variableDeclaration.Identifier );
            if ( variableDeclaration.Initializer != null )
            {
                Visit( variableDeclaration.Initializer );
            }
        }

        public virtual void Visit( BinaryExpression binaryExpression )
        {
            Visit( ( dynamic )binaryExpression );
        }

        public virtual void Visit( CallOperator callOperator )
        {
            Visit( callOperator.Identifier );
            foreach ( var argument in callOperator.Arguments )
            {
                Visit( argument );
            }
        }

        public virtual void Visit( Argument argument )
        {
            Visit( argument.Expression );
        }

        public virtual void Visit( Identifier identifier )
        {
            if ( identifier is TypeIdentifier )
            {
                Visit( ( TypeIdentifier )identifier );
            }
        }

        public virtual void Visit( UnaryExpression unaryExpression )
        {
            Visit( ( dynamic )unaryExpression );       
        }

        public virtual void Visit( AdditionOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( AssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( DivisionOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( EqualityOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( GreaterThanOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( GreaterThanOrEqualOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( LessThanOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( LessThanOrEqualOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( LogicalAndOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( LogicalOrOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( MultiplicationOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( NonEqualityOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( SubtractionOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( AdditionAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( AssignmentOperatorBase binaryOperator )
        {
            Visit( ( dynamic )binaryOperator );
        }

        public virtual void Visit( CompoundAssignmentOperator binaryOperator )
        {
            Visit( ( dynamic )binaryOperator );
        }

        public virtual void Visit( DivisionAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( MultiplicationAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( SubtractionAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( TypeIdentifier typeIdentifier )
        {
        }

        public virtual void Visit( BoolLiteral literal )
        {
        }

        public virtual void Visit( FloatLiteral literal )
        {
        }

        public virtual void Visit( IntLiteral literal )
        {
        }

        public virtual void Visit( StringLiteral literal )
        {
        }

        public virtual void Visit( LogicalNotOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( NegationOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( PostfixDecrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( PostfixIncrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( PostfixOperator unaryOperator )
        {
            Visit( ( dynamic )( unaryOperator ) );
        }

        public virtual void Visit( PrefixDecrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( PrefixIncrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( PrefixOperator prefixOperator )
        {
            Visit( ( dynamic )prefixOperator );
        }

        public virtual void Visit( EnumDeclaration enumDeclaration )
        {
            Visit( enumDeclaration.Identifier );

            foreach ( var enumValueDeclaration in enumDeclaration.Values )
            {
                Visit( enumValueDeclaration );
            }
        }

        public virtual void Visit( EnumValueDeclaration enumValueDeclaration )
        {
            Visit( enumValueDeclaration.Identifier );
            Visit( enumValueDeclaration.Value );
        }

        public virtual void Visit( MemberAccessExpression memberAccessExpression )
        {
            Visit( memberAccessExpression.Operand );
            Visit( memberAccessExpression.Member );
        }

        public virtual void Visit( FlowScriptSwitchLabel switchLabel )
        {
            Visit( ( dynamic ) switchLabel );
        }

        public virtual void Visit( ConditionSwitchLabel switchLabel )
        {
            Visit( switchLabel.Condition );
            foreach ( var statement in switchLabel.Body )
            {
                Visit( statement );
            }
        }

        public virtual void Visit( DefaultSwitchLabel switchLabel )
        {
            foreach ( var statement in switchLabel.Body )
            {
                Visit( statement );
            }
        }
    }
}
