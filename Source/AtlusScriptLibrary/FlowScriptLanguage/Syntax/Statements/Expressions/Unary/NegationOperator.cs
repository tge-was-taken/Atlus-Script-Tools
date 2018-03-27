namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class NegationOperator : PrefixOperator
    {
        public NegationOperator()
        {

        }

        public NegationOperator( Expression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"-({Operand})";
        }
    }
}
