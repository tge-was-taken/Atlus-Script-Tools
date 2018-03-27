using System.Collections.Generic;
using System.Linq;
using System.Text;
using AtlusScriptLibrary.Common.Libraries;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class FunctionDeclaration : Declaration
    {
        public IntLiteral Index { get; set; }

        public TypeIdentifier ReturnType { get; set; }

        public List<Parameter> Parameters { get; set; }

        public FunctionDeclaration() : base(DeclarationType.Function)
        {
            Parameters = new List<Parameter>();
        }

        public FunctionDeclaration( IntLiteral index, TypeIdentifier returnType, Identifier identifier, params Parameter[] parameters )
            : base( DeclarationType.Function, identifier )
        {
            Index = index;
            ReturnType = returnType;
            Parameters = parameters.ToList();
        }

        public FunctionDeclaration( IntLiteral index, TypeIdentifier returnType, Identifier identifier, List<Parameter> parameters )
            : base( DeclarationType.Function, identifier )
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
                builder.Append( Parameters[0] );

            for ( int i = 1; i < Parameters.Count; i++ )
            {
                builder.Append( $", {Parameters[i]}" );
            }

            builder.Append( ")" );

            return builder.ToString();
        }

        public static FunctionDeclaration FromLibraryFunction( FlowScriptModuleFunction libraryFunction )
        {
            var functionParameters = new List<Parameter>();
            foreach ( var libraryFunctionParameter in libraryFunction.Parameters )
            {
                functionParameters.Add( new Parameter(
                                             ParameterModifier.None,
                                            new TypeIdentifier( libraryFunctionParameter.Type ),
                                            new Identifier( libraryFunctionParameter.Name ) ) );
            }

            var functionDeclaration = new FunctionDeclaration(
                new IntLiteral( libraryFunction.Index ),
                new TypeIdentifier( libraryFunction.ReturnType ),
                new Identifier( libraryFunction.Name ),
                functionParameters );

            return functionDeclaration;
        }
    }
}
