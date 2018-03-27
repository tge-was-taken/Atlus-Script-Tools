namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class MultiplicationAssignmentOperator : CompoundAssignmentOperator
    {
        public MultiplicationAssignmentOperator()
        {

        }

        public MultiplicationAssignmentOperator( Expression left, Expression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} *= ({Right})";
        }
    }
}
