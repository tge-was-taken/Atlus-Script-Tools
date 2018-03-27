namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class SubtractionAssignmentOperator : CompoundAssignmentOperator
    {
        public SubtractionAssignmentOperator()
        {

        }

        public SubtractionAssignmentOperator( Expression left, Expression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} -= ({Right})";
        }
    }
}
