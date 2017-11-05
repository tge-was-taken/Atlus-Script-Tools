using System.Collections.Generic;
using System.Text;
using AtlusScriptLib.Common.Registry;
using AtlusScriptLib.FlowScriptLanguage.Decompiler;

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

        public static FlowScriptVariableDeclaration FromLibraryConstant( FlowScriptLibraryConstant libraryConstant )
        {
            var modifier = new FlowScriptVariableModifier( FlowScriptModifierType.Constant );
            var type = new FlowScriptTypeIdentifier( FlowScriptKeywordConverter.KeywordToValueType[ libraryConstant.Type ] );
            var identifier = new FlowScriptIdentifier( type.ValueType, libraryConstant.Name );
            var initializer = FlowScriptExpression.FromText( libraryConstant.Value );

            return new FlowScriptVariableDeclaration( modifier, type, identifier, initializer );
        }
    }
}
