namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptAssignmentOperatorBase : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 15;

        public FlowScriptAssignmentOperatorBase() : base( FlowScriptValueType.Unresolved )
        {
        }
    }

    public class FlowScriptAssignmentOperator : FlowScriptAssignmentOperatorBase
    {
        public override string ToString()
        {
            return $"{Left} = ({Right})";
        }
    }

    public abstract class FlowScriptCompoundAssignmentOperator : FlowScriptAssignmentOperatorBase
    {

    }

    public class FlowScriptAdditionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public override string ToString()
        {
            return $"{Left} += ({Right})";
        }
    }

    public class FlowScriptSubtractionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public override string ToString()
        {
            return $"{Left} -= ({Right})";
        }
    }

    public class FlowScriptMultiplicationAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public override string ToString()
        {
            return $"{Left} *= ({Right})";
        }
    }

    public class FlowScriptDivisionAssignmentOperator : FlowScriptCompoundAssignmentOperator
    {
        public override string ToString()
        {
            return $"{Left} *= ({Right})";
        }
    }
}
