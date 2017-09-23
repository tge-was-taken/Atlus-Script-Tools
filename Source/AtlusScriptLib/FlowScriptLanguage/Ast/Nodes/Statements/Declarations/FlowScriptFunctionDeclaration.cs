using System.Collections.Generic;
using System.Text;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptFunctionDeclaration : FlowScriptDeclaration
    {
        public FlowScriptTypeIdentifier ReturnType { get; set; }

        public FlowScriptIntLiteral Index { get; set; }

        public List<FlowScriptParameter> Parameters { get; set; }

        public FlowScriptFunctionDeclaration() : base(FlowScriptDeclarationType.Function)
        {
            Parameters = new List<FlowScriptParameter>();
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            builder.Append( $"{ReturnType.ToString()} func({Index.ToString()}) {Identifier.ToString()}(" );
            if ( Parameters.Count > 0 )
                builder.Append( Parameters[0].ToString() );

            for ( int i = 1; i < Parameters.Count; i++ )
            {
                builder.Append( $" {Parameters[i].ToString()}" );
            }

            builder.Append( ");" );

            return builder.ToString();
        }
    }
}
