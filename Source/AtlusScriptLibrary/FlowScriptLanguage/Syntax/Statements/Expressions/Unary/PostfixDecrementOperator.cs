namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{

    public class PostfixDecrementOperator : PostfixOperator
    {
        public PostfixDecrementOperator()
        {

        }

        public PostfixDecrementOperator( Expression operand ) : base( operand )
        {

        }

        public override string ToString()
        {
            return $"({Operand})--";
        }
    }
}
