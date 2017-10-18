using System.Collections.Generic;
using System.Text;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptVariableDeclaration : FlowScriptDeclaration
    {
        public FlowScriptVariableModifier Modifier { get; set; }

        public FlowScriptTypeIdentifier Type { get; set; }

        public FlowScriptExpression Initializer { get; set; }

        public FlowScriptVariableDeclaration() : base( FlowScriptDeclarationType.Variable )
        {
            Modifier = new FlowScriptVariableModifier();
        }

        public FlowScriptVariableDeclaration( FlowScriptVariableModifier modifier, FlowScriptTypeIdentifier type, FlowScriptIdentifier identifier, FlowScriptExpression initializer )
            : base( FlowScriptDeclarationType.Variable, identifier )
        {
            Modifier = modifier;
            Type = type;
            Initializer = initializer;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            builder.Append( $"{Modifier.ToString()} " );

            builder.Append( $"{Type.ToString()} {Identifier.ToString()}" );
            if ( Initializer != null )
            {
                builder.Append( $" = {Initializer.ToString()}" );
            }

            return builder.ToString();
        }
    }
}
