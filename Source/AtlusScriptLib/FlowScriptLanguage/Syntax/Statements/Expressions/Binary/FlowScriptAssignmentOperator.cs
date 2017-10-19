namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptAssignmentOperatorBase : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 15;

        protected FlowScriptAssignmentOperatorBase() : base( FlowScriptValueType.Unresolved )
        {
        }

        protected FlowScriptAssignmentOperatorBase( FlowScriptExpression left, FlowScriptExpression right )
            : base( FlowScriptValueType.Unresolved, left, right )
        {

        }
    }

    public class FlowScriptAssignmentOperator : FlowScriptAssignmentOperatorBase
    {
        public FlowScriptAssignmentOperator()
        {
        }

        public FlowScriptAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} = ({Right})";
        }
    }

    public abstract class FlowScriptCompoundAssignmentOperator : FlowScriptAssignmentOperatorBase
    {
        protected FlowScriptCompoundAssignmentOperator()
        {

        }

        protected FlowScriptCompoundAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }
    }

    public class FlowScriptAdditionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptAdditionAssignmentOperator()
        {

        }

        public FlowScriptAdditionAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} += ({Right})";
        }
    }

    public class FlowScriptSubtractionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptSubtractionAssignmentOperator()
        {

        }

        public FlowScriptSubtractionAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} -= ({Right})";
        }
    }

    public class FlowScriptMultiplicationAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptMultiplicationAssignmentOperator()
        {

        }

        public FlowScriptMultiplicationAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} *= ({Right})";
        }
    }

    public class FlowScriptDivisionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public FlowScriptDivisionAssignmentOperator()
        {

        }

        public FlowScriptDivisionAssignmentOperator( FlowScriptExpression left, FlowScriptExpression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} *= ({Right})";
        }
    }
}
