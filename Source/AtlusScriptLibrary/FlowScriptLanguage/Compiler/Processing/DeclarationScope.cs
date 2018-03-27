using System.Collections.Generic;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Compiler.Processing
{
    public class DeclarationScope
    {
        public DeclarationScope Parent { get; }

        public Dictionary<string, Declaration> Declarations { get; }

        public DeclarationScope( DeclarationScope parent )
        {
            Parent = parent;
            Declarations = new Dictionary<string, Declaration>();
        }

        public bool IsDeclared( Identifier identifier )
        {
            return TryGetDeclaration( identifier, out _ );
        }

        public bool TryRegisterDeclaration( Declaration declaration )
        {
            if ( IsDeclared( declaration.Identifier ) )
                return false;

            Declarations[declaration.Identifier.Text] = declaration;

            return true;
        }

        public bool TryGetDeclaration( Identifier identifier, out Declaration declaration )
        {
            if ( !Declarations.TryGetValue( identifier.Text, out declaration ) )
            {
                if ( Parent != null )
                {
                    return Parent.TryGetDeclaration( identifier, out declaration );
                }
                return false;
            }

            return true;
        }
    }
}
