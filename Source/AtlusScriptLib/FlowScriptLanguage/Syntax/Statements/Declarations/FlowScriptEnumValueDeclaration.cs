namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptEnumValueDeclaration : FlowScriptDeclaration
    {
        public FlowScriptExpression Value { get; set; }

        public FlowScriptEnumValueDeclaration() : base( FlowScriptDeclarationType.EnumLabel )
        {         
        }

        public FlowScriptEnumValueDeclaration( FlowScriptIdentifier identifier ) : base( FlowScriptDeclarationType.EnumLabel, identifier )
        {
        }

        public FlowScriptEnumValueDeclaration( FlowScriptIdentifier identifier, FlowScriptExpression value ) : base( FlowScriptDeclarationType.EnumLabel, identifier )
        {
            Value = value;
        }

        public override string ToString()
        {
            return $"{Identifier} = {Value}";
        }
    }
}