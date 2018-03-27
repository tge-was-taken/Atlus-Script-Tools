namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{

    public class AssignmentOperator : AssignmentOperatorBase
    {
        public AssignmentOperator()
        {
        }

        public AssignmentOperator( Expression left, Expression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} = ({Right})";
        }
    }
}
