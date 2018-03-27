using System.Collections.Generic;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class SyntaxNodeCollector<T> : SyntaxNodeVisitor where T : SyntaxNode
    {
        private readonly List<T> mCollectedNodes;

        private SyntaxNodeCollector()
        {
            mCollectedNodes = new List<T>();
        }

        public static List<T> Collect( SyntaxNode node )
        {
            var visitor = new SyntaxNodeCollector<T>();
            visitor.Visit( node );
            return visitor.mCollectedNodes;
        }

        public override void Visit( CompilationUnit compilationUnit )
        {
            if ( typeof( T ) == typeof( CompilationUnit ) )
                mCollectedNodes.Add( compilationUnit as T );

            base.Visit( compilationUnit );
        }

        public override void Visit( Import import )
        {
            if ( typeof( T ) == typeof( Import ) )
                mCollectedNodes.Add( import as T );

            base.Visit( import );
        }

        public override void Visit( Parameter parameter )
        {
            if ( typeof( T ) == typeof( Parameter ) )
                mCollectedNodes.Add( parameter as T );

            base.Visit( parameter );
        }

        public override void Visit( Statement statement )
        {
            if ( typeof( T ) == typeof( Statement ) )
                mCollectedNodes.Add( statement as T );

            base.Visit( statement );
        }

        public override void Visit( SyntaxNode syntaxNode )
        {
            if ( typeof( T ) == typeof( SyntaxNode ) )
                mCollectedNodes.Add( syntaxNode as T );

            base.Visit( syntaxNode );
        }

        public override void Visit( VariableModifier variableModifier )
        {
            if ( typeof( T ) == typeof( VariableModifier ) )
                mCollectedNodes.Add( variableModifier as T );

            base.Visit( variableModifier );
        }

        public override void Visit( BreakStatement breakStatement )
        {
            if ( typeof( T ) == typeof( BreakStatement ) )
                mCollectedNodes.Add( breakStatement as T );

            base.Visit( breakStatement );
        }

        public override void Visit( CompoundStatement compoundStatement )
        {
            if ( typeof( T ) == typeof( CompoundStatement ) )
                mCollectedNodes.Add( compoundStatement as T );

            base.Visit( compoundStatement );
        }

        public override void Visit( ContinueStatement continueStatement )
        {
            if ( typeof( T ) == typeof( ContinueStatement ) )
                mCollectedNodes.Add( continueStatement as T );

            base.Visit( continueStatement );
        }

        public override void Visit( Declaration declaration )
        {
            if ( typeof( T ) == typeof( Declaration ) )
                mCollectedNodes.Add( declaration as T );

            base.Visit( declaration );
        }

        public override void Visit( Expression expression )
        {
            if ( typeof( T ) == typeof( Expression ) )
                mCollectedNodes.Add( expression as T );

            base.Visit( expression );
        }

        public override void Visit( ForStatement forStatement )
        {
            if ( typeof( T ) == typeof( ForStatement ) )
                mCollectedNodes.Add( forStatement as T );

            base.Visit( forStatement );
        }

        public override void Visit( GotoStatement gotoStatement )
        {
            if ( typeof( T ) == typeof( GotoStatement ) )
                mCollectedNodes.Add( gotoStatement as T );

            base.Visit( gotoStatement );
        }

        public override void Visit( IfStatement ifStatement )
        {
            if ( typeof( T ) == typeof( IfStatement ) )
                mCollectedNodes.Add( ifStatement as T );

            base.Visit( ifStatement );
        }

        public override void Visit( NullStatement nullStatement )
        {
            if ( typeof( T ) == typeof( NullStatement ) )
                mCollectedNodes.Add( nullStatement as T );

            base.Visit( nullStatement );
        }

        public override void Visit( ReturnStatement returnStatement )
        {
            if ( typeof( T ) == typeof( ReturnStatement ) )
                mCollectedNodes.Add( returnStatement as T );

            base.Visit( returnStatement );
        }

        public override void Visit( SwitchStatement switchStatement )
        {
            if ( typeof( T ) == typeof( SwitchStatement ) )
                mCollectedNodes.Add( switchStatement as T );

            base.Visit( switchStatement );
        }

        public override void Visit( WhileStatement whileStatement )
        {
            if ( typeof( T ) == typeof( WhileStatement ) )
                mCollectedNodes.Add( whileStatement as T );

            base.Visit( whileStatement );
        }

        public override void Visit( FunctionDeclaration functionDeclaration )
        {
            if ( typeof( T ) == typeof( FunctionDeclaration ) )
                mCollectedNodes.Add( functionDeclaration as T );

            base.Visit( functionDeclaration );
        }

        public override void Visit( LabelDeclaration labelDeclaration )
        {
            if ( typeof( T ) == typeof( LabelDeclaration ) )
                mCollectedNodes.Add( labelDeclaration as T );

            base.Visit( labelDeclaration );
        }

        public override void Visit( ProcedureDeclaration procedureDeclaration )
        {
            if ( typeof( T ) == typeof( ProcedureDeclaration ) )
                mCollectedNodes.Add( procedureDeclaration as T );

            base.Visit( procedureDeclaration );
        }

        public override void Visit( VariableDeclaration variableDeclaration )
        {
            if ( typeof( T ) == typeof( VariableDeclaration ) )
                mCollectedNodes.Add( variableDeclaration as T );

            base.Visit( variableDeclaration );
        }

        public override void Visit( BinaryExpression binaryExpression )
        {
            if ( typeof( T ) == typeof( BinaryExpression ) )
                mCollectedNodes.Add( binaryExpression as T );

            base.Visit( binaryExpression );
        }

        public override void Visit( CallOperator callOperator )
        {
            if ( typeof( T ) == typeof( CallOperator ) )
                mCollectedNodes.Add( callOperator as T );

            base.Visit( callOperator );
        }

        public override void Visit( Identifier identifier )
        {
            if ( typeof( T ) == typeof( Identifier ) )
                mCollectedNodes.Add( identifier as T );

            base.Visit( identifier );
        }

        public override void Visit( UnaryExpression unaryExpression )
        {
            if ( typeof( T ) == typeof( UnaryExpression ) )
                mCollectedNodes.Add( unaryExpression as T );

            base.Visit( unaryExpression );
        }

        public override void Visit( AdditionOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( AdditionOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( AssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( AssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( DivisionOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( DivisionOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( EqualityOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( EqualityOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( GreaterThanOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( GreaterThanOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( GreaterThanOrEqualOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( GreaterThanOrEqualOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( LessThanOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( LessThanOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( LessThanOrEqualOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( LessThanOrEqualOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( LogicalAndOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( LogicalAndOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( LogicalOrOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( LogicalOrOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( MultiplicationOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( MultiplicationOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( NonEqualityOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( NonEqualityOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( SubtractionOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( SubtractionOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( AdditionAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( AdditionAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( AssignmentOperatorBase binaryOperator )
        {
            if ( typeof( T ) == typeof( AssignmentOperatorBase ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( CompoundAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( CompoundAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( DivisionAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( DivisionAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( MultiplicationAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( MultiplicationAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( SubtractionAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( SubtractionAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( TypeIdentifier typeIdentifier )
        {
            if ( typeof( T ) == typeof( TypeIdentifier ) )
                mCollectedNodes.Add( typeIdentifier as T );

            base.Visit( typeIdentifier );
        }

        public override void Visit( BoolLiteral literal )
        {
            if ( typeof( T ) == typeof( BoolLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( FloatLiteral literal )
        {
            if ( typeof( T ) == typeof( FloatLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( IntLiteral literal )
        {
            if ( typeof( T ) == typeof( IntLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( StringLiteral literal )
        {
            if ( typeof( T ) == typeof( StringLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( LogicalNotOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( LogicalNotOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( NegationOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( NegationOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( PostfixDecrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( PostfixDecrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( PostfixIncrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( PostfixIncrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( PostfixOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( PostfixOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( PrefixDecrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( PrefixDecrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( PrefixIncrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( PrefixIncrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( PrefixOperator prefixOperator )
        {
            if ( typeof( T ) == typeof( PrefixOperator ) )
                mCollectedNodes.Add( prefixOperator as T );

            base.Visit( prefixOperator );
        }

        public override void Visit( EnumDeclaration enumDeclaration )
        {
            if ( typeof( T ) == typeof( EnumDeclaration ) )
                mCollectedNodes.Add( enumDeclaration as T );

            base.Visit( enumDeclaration );
        }

        public override void Visit( EnumValueDeclaration enumValueDeclaration )
        {
            if ( typeof( T ) == typeof( EnumValueDeclaration ) )
                mCollectedNodes.Add( enumValueDeclaration as T );

            base.Visit( enumValueDeclaration );
        }

        public override void Visit( MemberAccessExpression memberAccessExpression )
        {
            if ( typeof( T ) == typeof( MemberAccessExpression ) )
                mCollectedNodes.Add( memberAccessExpression as T );

            base.Visit( memberAccessExpression );
        }

        public override void Visit( FlowScriptSwitchLabel switchLabel )
        {
            if ( typeof( T ) == typeof( FlowScriptSwitchLabel ) )
                mCollectedNodes.Add( switchLabel as T );

            base.Visit( switchLabel );
        }

        public override void Visit( ConditionSwitchLabel switchLabel )
        {
            if ( typeof( T ) == typeof( ConditionSwitchLabel ) )
                mCollectedNodes.Add( switchLabel as T );

            base.Visit( switchLabel );
        }

        public override void Visit( DefaultSwitchLabel switchLabel )
        {
            if ( typeof( T ) == typeof( DefaultSwitchLabel ) )
                mCollectedNodes.Add( switchLabel as T );

            base.Visit( switchLabel );
        }
    }
}
