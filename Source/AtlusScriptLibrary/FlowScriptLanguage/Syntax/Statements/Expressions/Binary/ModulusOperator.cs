namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class ModulusOperator : BinaryExpression, IOperator
    {
        public int Precedence => 5;

        public ModulusOperator() : base( ValueKind.Unresolved )
        {
        }

        public ModulusOperator( Expression left, Expression right )
            : base( ValueKind.Unresolved, left, right )
        {

        }

        public override string ToString()
        {
            return $"({Left}) % ({Right})";
        }
    }
}