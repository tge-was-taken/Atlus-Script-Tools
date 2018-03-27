namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public abstract class CompoundAssignmentOperator : AssignmentOperatorBase
    {
        protected CompoundAssignmentOperator()
        {

        }

        protected CompoundAssignmentOperator( Expression left, Expression right )
            : base( left, right )
        {
        }
    }
}
