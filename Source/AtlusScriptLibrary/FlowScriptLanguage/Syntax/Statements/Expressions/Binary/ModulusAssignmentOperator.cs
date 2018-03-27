namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class ModulusAssignmentOperator : CompoundAssignmentOperator
    {
        public ModulusAssignmentOperator()
        {

        }

        public ModulusAssignmentOperator( Expression left, Expression right )
            : base( left, right )
        {
        }

        public override string ToString()
        {
            return $"{Left} %= ({Right})";
        }
    }
}