using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptFunctionDeclaration : FlowScriptDeclaration
    {
        public FlowScriptIntLiteral Index { get; set; }

        public FlowScriptTypeIdentifier ReturnType { get; set; }

        public List<FlowScriptParameter> Parameters { get; set; }

        public FlowScriptFunctionDeclaration() : base(FlowScriptDeclarationType.Function)
        {
            Parameters = new List<FlowScriptParameter>();
        }

        public FlowScriptFunctionDeclaration( FlowScriptIntLiteral index, FlowScriptTypeIdentifier returnType, FlowScriptIdentifier identifier, params FlowScriptParameter[] parameters )
            : base( FlowScriptDeclarationType.Function, identifier )
        {
            Index = index;
            ReturnType = returnType;
            Parameters = parameters.ToList();
        }

        public FlowScriptFunctionDeclaration( FlowScriptIntLiteral index, FlowScriptTypeIdentifier returnType, FlowScriptIdentifier identifier, List<FlowScriptParameter> parameters )
            : base( FlowScriptDeclarationType.Function, identifier )
        {
            Index = index;
            ReturnType = returnType;
            Parameters = parameters;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            builder.Append( $"function( {Index} ) {ReturnType} {Identifier}(" );
            if ( Parameters.Count > 0 )
                builder.Append( Parameters[0].ToString() );

            for ( int i = 1; i < Parameters.Count; i++ )
            {
                builder.Append( $", {Parameters[i]}" );
            }

            builder.Append( ")" );

            return builder.ToString();
        }
    }
}
