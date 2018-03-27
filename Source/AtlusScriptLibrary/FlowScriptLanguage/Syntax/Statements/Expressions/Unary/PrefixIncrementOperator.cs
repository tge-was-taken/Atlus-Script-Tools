namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class PrefixIncrementOperator : PrefixOperator
    {
        public PrefixIncrementOperator()
        {

        }

        public PrefixIncrementOperator( Expression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"++({Operand})";
        }
    }
}
