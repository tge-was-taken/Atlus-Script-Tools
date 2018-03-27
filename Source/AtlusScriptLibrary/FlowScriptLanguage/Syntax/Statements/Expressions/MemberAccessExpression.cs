namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class MemberAccessExpression : Expression, IOperator
    {
        public Identifier Operand { get; set; }

        public Identifier Member { get; set; }

        public int Precedence => 2;

        public MemberAccessExpression() : base( ValueKind.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Operand}.{Member}";
        }
    }
}
