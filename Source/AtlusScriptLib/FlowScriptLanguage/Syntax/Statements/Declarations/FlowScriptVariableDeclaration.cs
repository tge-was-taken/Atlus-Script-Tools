using System.Collections.Generic;
using System.Text;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptVariableDeclaration : FlowScriptDeclaration
    {
        public List<FlowScriptVariableModifier> Modifiers { get; set; }

        public FlowScriptTypeIdentifier Type { get; set; }

        public FlowScriptExpression Initializer { get; set; }

        public FlowScriptVariableDeclaration() : base(FlowScriptDeclarationType.Variable)
        {
            Modifiers = new List<FlowScriptVariableModifier>();
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            foreach ( var mod in Modifiers )
            {
                builder.Append( $"{mod.ToString()} " );
            }

            builder.Append( $"{Type.ToString()} {Identifier.ToString()}" );
            if ( Initializer != null )
            {
                builder.Append( $" = {Initializer.ToString()};" );
            }

            return builder.ToString();
        }
    }
}
