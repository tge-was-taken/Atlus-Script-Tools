namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class AdditionAssignmentOperator : CompoundAssignmentOperator
    {
        public AdditionAssignmentOperator()
        {

        }

        public AdditionAssignmentOperator( Expression left, Expression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} += ({Right})";
        }
    }
}
