using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptSyntaxVisitor
    {
        public virtual void Visit( FlowScriptCompilationUnit compilationUnit )
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

        public virtual void Visit( FlowScriptImport import )
        {
        }

        public virtual void Visit( FlowScriptParameter parameter )
        {
            Visit( parameter.Type );
            Visit( parameter.Identifier );
        }

        public virtual void Visit( FlowScriptStatement statement )
        {
            Visit( ( dynamic )statement );
        }

        public virtual void Visit( FlowScriptSyntaxNode syntaxNode )
        {
            Visit( ( dynamic )syntaxNode );
        }

        public virtual void Visit( FlowScriptVariableModifier variableModifier )
        {
        }

        public virtual void Visit( FlowScriptBreakStatement breakStatement )
        {
        }

        public virtual void Visit( FlowScriptCompoundStatement compoundStatement )
        {
            foreach ( var statement in compoundStatement )
            {
                Visit( statement );
            }
        }

        public virtual void Visit( FlowScriptContinueStatement continueStatement )
        {
        }

        public virtual void Visit( FlowScriptDeclaration declaration )
        {
            Visit( ( dynamic )declaration );
        }

        public virtual void Visit( FlowScriptExpression expression )
        {
            Visit( ( dynamic )expression );
        }

        public virtual void Visit( FlowScriptForStatement forStatement )
        {
            Visit( (dynamic)forStatement.Condition );
            Visit( (dynamic)forStatement.AfterLoop );
            if ( forStatement.Body != null )
                Visit( forStatement.Body );
        }

        public virtual void Visit( FlowScriptGotoStatement gotoStatement )
        {
            Visit( gotoStatement.LabelIdentifier );
        }

        public virtual void Visit( FlowScriptIfStatement ifStatement )
        {
            Visit( (dynamic)ifStatement.Condition );

            if ( ifStatement.Body != null )
                Visit( ifStatement.Body );

            if ( ifStatement.ElseBody != null )
                Visit( ifStatement.ElseBody );
        }

        public virtual void Visit( FlowScriptNullStatement nullStatement )
        {
        }

        public virtual void Visit( FlowScriptReturnStatement returnStatement )
        {
            if ( returnStatement.Value != null )
            {
                Visit( (dynamic)returnStatement.Value );
            }
        }

        public virtual void Visit( FlowScriptSwitchStatement switchStatement )
        {
            Visit( (dynamic)switchStatement.SwitchOn );
            foreach ( var label in switchStatement.Labels )
            {
                Visit( ( dynamic )label );
            }
        }

        public virtual void Visit( FlowScriptWhileStatement whileStatement )
        {
            Visit( ( dynamic )whileStatement.Condition );
            Visit( whileStatement.Body );
        }

        public virtual void Visit( FlowScriptFunctionDeclaration functionDeclaration )
        {
            Visit( functionDeclaration.Index );
            Visit( functionDeclaration.ReturnType );
            Visit( functionDeclaration.Identifier );
            foreach ( var parameter in functionDeclaration.Parameters )
            {
                Visit( parameter );
            }     
        }

        public virtual void Visit( FlowScriptLabelDeclaration labelDeclaration )
        {
            Visit( labelDeclaration.Identifier );
        }

        public virtual void Visit( FlowScriptProcedureDeclaration procedureDeclaration )
        {
            Visit( procedureDeclaration.ReturnType );
            Visit( procedureDeclaration.Identifier );
            foreach ( var parameter in procedureDeclaration.Parameters )
            {
                Visit( parameter );
            }
            Visit( procedureDeclaration.Body );
        }

        public virtual void Visit( FlowScriptVariableDeclaration variableDeclaration )
        {
            Visit( variableDeclaration.Modifier );
            Visit( variableDeclaration.Type );
            Visit( variableDeclaration.Identifier );
            if ( variableDeclaration.Initializer != null )
            {
                Visit( variableDeclaration.Initializer );
            }
        }

        public virtual void Visit( FlowScriptBinaryExpression binaryExpression )
        {
            Visit( ( dynamic )binaryExpression );
        }

        public virtual void Visit( FlowScriptCallOperator callOperator )
        {
            Visit( callOperator.Identifier );
            foreach ( var argument in callOperator.Arguments )
            {
                Visit( argument );
            }
        }

        public virtual void Visit( FlowScriptIdentifier identifier )
        {
            if ( identifier is FlowScriptTypeIdentifier )
            {
                Visit( ( FlowScriptTypeIdentifier )identifier );
            }
        }

        public virtual void Visit( FlowScriptUnaryExpression unaryExpression )
        {
            Visit( ( dynamic )unaryExpression );       
        }

        public virtual void Visit( FlowScriptAdditionOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptDivisionOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptEqualityOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptGreaterThanOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptGreaterThanOrEqualOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptLessThanOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptLessThanOrEqualOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptLogicalAndOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptLogicalOrOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptMultiplicationOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptNonEqualityOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptSubtractionOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptAdditionAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptAssignmentOperatorBase binaryOperator )
        {
            Visit( ( dynamic )binaryOperator );
        }

        public virtual void Visit( FlowScriptCompoundAssignmentOperator binaryOperator )
        {
            Visit( ( dynamic )binaryOperator );
        }

        public virtual void Visit( FlowScriptDivisionAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptMultiplicationAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptSubtractionAssignmentOperator binaryOperator )
        {
            Visit( binaryOperator.Left );
            Visit( binaryOperator.Right );
        }

        public virtual void Visit( FlowScriptTypeIdentifier typeIdentifier )
        {
        }

        public virtual void Visit( FlowScriptBoolLiteral literal )
        {
        }

        public virtual void Visit( FlowScriptFloatLiteral literal )
        {
        }

        public virtual void Visit( FlowScriptIntLiteral literal )
        {
        }

        public virtual void Visit( FlowScriptStringLiteral literal )
        {
        }

        public virtual void Visit( FlowScriptBitwiseNotOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( FlowScriptLogicalNotOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( FlowScriptNegationOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( FlowScriptPostfixDecrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( FlowScriptPostfixIncrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( FlowScriptPostfixOperator unaryOperator )
        {
            Visit( ( dynamic )( unaryOperator ) );
        }

        public virtual void Visit( FlowScriptPrefixDecrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( FlowScriptPrefixIncrementOperator unaryOperator )
        {
            Visit( unaryOperator.Operand );
        }

        public virtual void Visit( FlowScriptPrefixOperator prefixOperator )
        {
            Visit( ( dynamic )prefixOperator );
        }
    }
}
