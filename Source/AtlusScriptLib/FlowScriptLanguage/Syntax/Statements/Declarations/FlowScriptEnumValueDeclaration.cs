namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptEnumValueDeclaration : FlowScriptDeclaration
    {
        public FlowScriptExpression Value { get; set; }

        public FlowScriptEnumValueDeclaration() : base( FlowScriptDeclarationType.EnumLabel )
        {         
        }

        public override string ToString()
        {
            return $"{Identifier} = {Value}";
        }
    }
}