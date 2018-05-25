using System.Text;
using AtlusScriptLibrary.Common.Libraries;
using AtlusScriptLibrary.FlowScriptLanguage.Decompiler;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class VariableDeclaration : Declaration
    {
        public VariableModifier Modifier { get; set; }

        public TypeIdentifier Type { get; set; }

        public Expression Initializer { get; set; }

        public virtual bool IsArray => false;

        public VariableDeclaration() : base( DeclarationType.Variable )
        {
            Modifier = new VariableModifier();
        }

        public VariableDeclaration( VariableModifier modifier, TypeIdentifier type, Identifier identifier, Expression initializer )
            : base( DeclarationType.Variable, identifier )
        {
            Modifier = modifier;
            Type = type;
            Initializer = initializer;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            builder.Append( $"{Modifier} " );

            builder.Append( $"{Type} {Identifier}" );
            if ( Initializer != null )
            {
                builder.Append( $" = {Initializer}" );
            }

            return builder.ToString();
        }

        public static VariableDeclaration FromLibraryConstant( FlowScriptModuleConstant libraryConstant )
        {
            var modifier = new VariableModifier( VariableModifierKind.Constant );
            var type = new TypeIdentifier( KeywordDictionary.KeywordToValueType[ libraryConstant.Type ] );
            var identifier = new Identifier( type.ValueKind, libraryConstant.Name );
            var initializer = Expression.FromText( libraryConstant.Value );

            return new VariableDeclaration( modifier, type, identifier, initializer );
        }
    }

    public class ArrayVariableDeclaration : VariableDeclaration
    {
        public IntLiteral Size { get; set; }

        public override bool IsArray => true;

        public ArrayVariableDeclaration()
        {
        }

        public ArrayVariableDeclaration( VariableModifier modifier, TypeIdentifier type, Identifier identifier, IntLiteral size, Expression initializer )
            : base( modifier, type, identifier, initializer )
        {
            Size = size;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            builder.Append( $"{Modifier} " );

            builder.Append( $"{Type} {Identifier}[{Size}]" );
            if ( Initializer != null )
            {
                builder.Append( $" = {Initializer}" );
            }

            return builder.ToString();
        }
    }
}
