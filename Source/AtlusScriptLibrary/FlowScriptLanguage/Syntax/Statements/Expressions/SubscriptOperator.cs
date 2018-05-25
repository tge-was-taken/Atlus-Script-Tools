namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class SubscriptOperator : Expression, IOperator
    {
        public Identifier Operand { get; set; }

        public Expression Index { get; set; }

        public int Precedence => 2;

        public SubscriptOperator() : base( ValueKind.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Operand}[ {Index} ]";
        }
    }
}