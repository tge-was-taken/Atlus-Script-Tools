namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class Argument : SyntaxNode
    {
        public ArgumentModifier Modifier { get; set; }

        public Expression Expression { get; set; }

        public Argument()
        {
        }

        public Argument( Expression expression )
        {
            Modifier = ArgumentModifier.None;
            Expression = expression;
        }

        public Argument( ArgumentModifier modifier, Expression expression )
        {
            Modifier = modifier;
            Expression = expression;
        }

        public override string ToString()
        {
            return $"{Modifier} {Expression}";
        }
    }
}