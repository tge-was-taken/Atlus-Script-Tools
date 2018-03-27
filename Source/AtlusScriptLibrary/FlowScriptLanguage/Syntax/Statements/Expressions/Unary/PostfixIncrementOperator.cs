namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class PostfixIncrementOperator : PostfixOperator
    {
        public PostfixIncrementOperator()
        {

        }

        public PostfixIncrementOperator( Expression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"({Operand})++";
        }
    }
}
