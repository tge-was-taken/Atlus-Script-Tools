using System.Text;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class IfStatement : Statement
    {
        public Expression Condition { get; set; }

        public CompoundStatement Body { get; set; }

        public CompoundStatement ElseBody { get; set; }

        public IfStatement()
        {
        }

        public IfStatement( Expression expression, CompoundStatement body, CompoundStatement elseBody )
        {
            Condition = expression;
            Body = body;
            ElseBody = elseBody;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append( $"if ( {Condition} ) {Body}" );
            if ( ElseBody != null )
            {
                builder.Append( $" else {ElseBody}" );
            }

            return builder.ToString();
        }
    }
}
