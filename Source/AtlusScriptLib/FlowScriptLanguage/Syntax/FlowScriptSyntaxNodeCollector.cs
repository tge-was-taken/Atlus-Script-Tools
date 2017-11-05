using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptSyntaxNodeCollector<T> : FlowScriptSyntaxVisitor where T : FlowScriptSyntaxNode
    {
        private readonly List<T> mCollectedNodes;

        private FlowScriptSyntaxNodeCollector()
        {
            mCollectedNodes = new List<T>();
        }

        public static List<T> Collect( FlowScriptSyntaxNode node )
        {
            var visitor = new FlowScriptSyntaxNodeCollector<T>();
            visitor.Visit( node );
            return visitor.mCollectedNodes;
        }

        public override void Visit( FlowScriptCompilationUnit compilationUnit )
        {
            if ( typeof( T ) == typeof( FlowScriptCompilationUnit ) )
                mCollectedNodes.Add( compilationUnit as T );

            base.Visit( compilationUnit );
        }

        public override void Visit( FlowScriptImport import )
        {
            if ( typeof( T ) == typeof( FlowScriptImport ) )
                mCollectedNodes.Add( import as T );

            base.Visit( import );
        }

        public override void Visit( FlowScriptParameter parameter )
        {
            if ( typeof( T ) == typeof( FlowScriptParameter ) )
                mCollectedNodes.Add( parameter as T );

            base.Visit( parameter );
        }

        public override void Visit( FlowScriptStatement statement )
        {
            if ( typeof( T ) == typeof( FlowScriptStatement ) )
                mCollectedNodes.Add( statement as T );

            base.Visit( statement );
        }

        public override void Visit( FlowScriptSyntaxNode syntaxNode )
        {
            if ( typeof( T ) == typeof( FlowScriptSyntaxNode ) )
                mCollectedNodes.Add( syntaxNode as T );

            base.Visit( syntaxNode );
        }

        public override void Visit( FlowScriptVariableModifier variableModifier )
        {
            if ( typeof( T ) == typeof( FlowScriptVariableModifier ) )
                mCollectedNodes.Add( variableModifier as T );

            base.Visit( variableModifier );
        }

        public override void Visit( FlowScriptBreakStatement breakStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptBreakStatement ) )
                mCollectedNodes.Add( breakStatement as T );

            base.Visit( breakStatement );
        }

        public override void Visit( FlowScriptCompoundStatement compoundStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptCompoundStatement ) )
                mCollectedNodes.Add( compoundStatement as T );

            base.Visit( compoundStatement );
        }

        public override void Visit( FlowScriptContinueStatement continueStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptContinueStatement ) )
                mCollectedNodes.Add( continueStatement as T );

            base.Visit( continueStatement );
        }

        public override void Visit( FlowScriptDeclaration declaration )
        {
            if ( typeof( T ) == typeof( FlowScriptDeclaration ) )
                mCollectedNodes.Add( declaration as T );

            base.Visit( declaration );
        }

        public override void Visit( FlowScriptExpression expression )
        {
            if ( typeof( T ) == typeof( FlowScriptExpression ) )
                mCollectedNodes.Add( expression as T );

            base.Visit( expression );
        }

        public override void Visit( FlowScriptForStatement forStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptForStatement ) )
                mCollectedNodes.Add( forStatement as T );

            base.Visit( forStatement );
        }

        public override void Visit( FlowScriptGotoStatement gotoStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptGotoStatement ) )
                mCollectedNodes.Add( gotoStatement as T );

            base.Visit( gotoStatement );
        }

        public override void Visit( FlowScriptIfStatement ifStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptIfStatement ) )
                mCollectedNodes.Add( ifStatement as T );

            base.Visit( ifStatement );
        }

        public override void Visit( FlowScriptNullStatement nullStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptNullStatement ) )
                mCollectedNodes.Add( nullStatement as T );

            base.Visit( nullStatement );
        }

        public override void Visit( FlowScriptReturnStatement returnStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptReturnStatement ) )
                mCollectedNodes.Add( returnStatement as T );

            base.Visit( returnStatement );
        }

        public override void Visit( FlowScriptSwitchStatement switchStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptSwitchStatement ) )
                mCollectedNodes.Add( switchStatement as T );

            base.Visit( switchStatement );
        }

        public override void Visit( FlowScriptWhileStatement whileStatement )
        {
            if ( typeof( T ) == typeof( FlowScriptWhileStatement ) )
                mCollectedNodes.Add( whileStatement as T );

            base.Visit( whileStatement );
        }

        public override void Visit( FlowScriptFunctionDeclaration functionDeclaration )
        {
            if ( typeof( T ) == typeof( FlowScriptFunctionDeclaration ) )
                mCollectedNodes.Add( functionDeclaration as T );

            base.Visit( functionDeclaration );
        }

        public override void Visit( FlowScriptLabelDeclaration labelDeclaration )
        {
            if ( typeof( T ) == typeof( FlowScriptLabelDeclaration ) )
                mCollectedNodes.Add( labelDeclaration as T );

            base.Visit( labelDeclaration );
        }

        public override void Visit( FlowScriptProcedureDeclaration procedureDeclaration )
        {
            if ( typeof( T ) == typeof( FlowScriptProcedureDeclaration ) )
                mCollectedNodes.Add( procedureDeclaration as T );

            base.Visit( procedureDeclaration );
        }

        public override void Visit( FlowScriptVariableDeclaration variableDeclaration )
        {
            if ( typeof( T ) == typeof( FlowScriptVariableDeclaration ) )
                mCollectedNodes.Add( variableDeclaration as T );

            base.Visit( variableDeclaration );
        }

        public override void Visit( FlowScriptBinaryExpression binaryExpression )
        {
            if ( typeof( T ) == typeof( FlowScriptBinaryExpression ) )
                mCollectedNodes.Add( binaryExpression as T );

            base.Visit( binaryExpression );
        }

        public override void Visit( FlowScriptCallOperator callOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptCallOperator ) )
                mCollectedNodes.Add( callOperator as T );

            base.Visit( callOperator );
        }

        public override void Visit( FlowScriptIdentifier identifier )
        {
            if ( typeof( T ) == typeof( FlowScriptIdentifier ) )
                mCollectedNodes.Add( identifier as T );

            base.Visit( identifier );
        }

        public override void Visit( FlowScriptUnaryExpression unaryExpression )
        {
            if ( typeof( T ) == typeof( FlowScriptUnaryExpression ) )
                mCollectedNodes.Add( unaryExpression as T );

            base.Visit( unaryExpression );
        }

        public override void Visit( FlowScriptAdditionOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptAdditionOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptDivisionOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptDivisionOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptEqualityOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptEqualityOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptGreaterThanOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptGreaterThanOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptGreaterThanOrEqualOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptGreaterThanOrEqualOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptLessThanOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptLessThanOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptLessThanOrEqualOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptLessThanOrEqualOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptLogicalAndOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptLogicalAndOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptLogicalOrOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptLogicalOrOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptMultiplicationOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptMultiplicationOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptNonEqualityOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptNonEqualityOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptSubtractionOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptSubtractionOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptAdditionAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptAdditionAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptAssignmentOperatorBase binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptAssignmentOperatorBase ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptCompoundAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptCompoundAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptDivisionAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptDivisionAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptMultiplicationAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptMultiplicationAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptSubtractionAssignmentOperator binaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptSubtractionAssignmentOperator ) )
                mCollectedNodes.Add( binaryOperator as T );

            base.Visit( binaryOperator );
        }

        public override void Visit( FlowScriptTypeIdentifier typeIdentifier )
        {
            if ( typeof( T ) == typeof( FlowScriptTypeIdentifier ) )
                mCollectedNodes.Add( typeIdentifier as T );

            base.Visit( typeIdentifier );
        }

        public override void Visit( FlowScriptBoolLiteral literal )
        {
            if ( typeof( T ) == typeof( FlowScriptBoolLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( FlowScriptFloatLiteral literal )
        {
            if ( typeof( T ) == typeof( FlowScriptFloatLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( FlowScriptIntLiteral literal )
        {
            if ( typeof( T ) == typeof( FlowScriptIntLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( FlowScriptStringLiteral literal )
        {
            if ( typeof( T ) == typeof( FlowScriptStringLiteral ) )
                mCollectedNodes.Add( literal as T );

            base.Visit( literal );
        }

        public override void Visit( FlowScriptLogicalNotOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptLogicalNotOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( FlowScriptNegationOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptNegationOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( FlowScriptPostfixDecrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptPostfixDecrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( FlowScriptPostfixIncrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptPostfixIncrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( FlowScriptPostfixOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptPostfixOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( FlowScriptPrefixDecrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptPrefixDecrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( FlowScriptPrefixIncrementOperator unaryOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptPrefixIncrementOperator ) )
                mCollectedNodes.Add( unaryOperator as T );

            base.Visit( unaryOperator );
        }

        public override void Visit( FlowScriptPrefixOperator prefixOperator )
        {
            if ( typeof( T ) == typeof( FlowScriptPrefixOperator ) )
                mCollectedNodes.Add( prefixOperator as T );

            base.Visit( prefixOperator );
        }

        public override void Visit( FlowScriptEnumDeclaration enumDeclaration )
        {
            if ( typeof( T ) == typeof( FlowScriptEnumDeclaration ) )
                mCollectedNodes.Add( enumDeclaration as T );

            base.Visit( enumDeclaration );
        }

        public override void Visit( FlowScriptEnumValueDeclaration enumValueDeclaration )
        {
            if ( typeof( T ) == typeof( FlowScriptEnumValueDeclaration ) )
                mCollectedNodes.Add( enumValueDeclaration as T );

            base.Visit( enumValueDeclaration );
        }

        public override void Visit( FlowScriptMemberAccessExpression memberAccessExpression )
        {
            if ( typeof( T ) == typeof( FlowScriptMemberAccessExpression ) )
                mCollectedNodes.Add( memberAccessExpression as T );

            base.Visit( memberAccessExpression );
        }

        public override void Visit( FlowScriptSwitchLabel switchLabel )
        {
            if ( typeof( T ) == typeof( FlowScriptSwitchLabel ) )
                mCollectedNodes.Add( switchLabel as T );

            base.Visit( switchLabel );
        }

        public override void Visit( FlowScriptConditionSwitchLabel switchLabel )
        {
            if ( typeof( T ) == typeof( FlowScriptConditionSwitchLabel ) )
                mCollectedNodes.Add( switchLabel as T );

            base.Visit( switchLabel );
        }

        public override void Visit( FlowScriptDefaultSwitchLabel switchLabel )
        {
            if ( typeof( T ) == typeof( FlowScriptDefaultSwitchLabel ) )
                mCollectedNodes.Add( switchLabel as T );

            base.Visit( switchLabel );
        }
    }
}
