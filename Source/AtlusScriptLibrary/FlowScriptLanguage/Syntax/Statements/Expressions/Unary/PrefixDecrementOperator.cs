namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{

    public class PrefixDecrementOperator : PrefixOperator
    {
        public PrefixDecrementOperator()
        {

        }

        public PrefixDecrementOperator( Expression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"--({Operand})";
        }
    }
}
