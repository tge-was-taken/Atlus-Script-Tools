using System.Collections.Generic;
using System.Text;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class ProcedureDeclaration : Declaration
    {
        public IntLiteral Index { get; set; }

        public TypeIdentifier ReturnType { get; set; }

        public List<Parameter> Parameters { get; set; }

        public CompoundStatement Body { get; set; }

        public ProcedureDeclaration() : base(DeclarationType.Procedure)
        {
            Parameters = new List<Parameter>();
        }

        public ProcedureDeclaration( TypeIdentifier returnType, Identifier identifier, List<Parameter> parameters, CompoundStatement body ) : base( DeclarationType.Procedure, identifier )
        {
            ReturnType = returnType;
            Parameters = parameters;
            Body = body;
        }

        public ProcedureDeclaration( IntLiteral index, TypeIdentifier returnType, Identifier identifier, List<Parameter> parameters, CompoundStatement body ) : base( DeclarationType.Procedure, identifier )
        {
            Index = index;
            ReturnType = returnType;
            Parameters = parameters;
            Body       = body;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            builder.Append( $"{ReturnType} {Identifier}(" );
            if ( Parameters.Count > 0 )
                builder.Append( Parameters[0] );

            for ( int i = 1; i < Parameters.Count; i++ )
            {
                builder.Append( $", {Parameters[i]}" );
            }

            builder.Append( ")" );

            if ( Body != null )
            {
                builder.Append( $"{{ {Body} }}" );
            }

            return builder.ToString();
        }
    }
}
