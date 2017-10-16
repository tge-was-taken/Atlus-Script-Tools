using System.Collections.Generic;

using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Compiler.Processing
{
    public class FlowScriptDeclarationScope
    {
        public FlowScriptDeclarationScope Parent { get; }

        public Dictionary<string, FlowScriptDeclaration> Declarations { get; }

        public FlowScriptDeclarationScope( FlowScriptDeclarationScope parent )
        {
            Parent = parent;
            Declarations = new Dictionary<string, FlowScriptDeclaration>();
        }

        public bool IsDeclared( FlowScriptIdentifier identifier )
        {
            return TryGetDeclaration( identifier, out _ );
        }

        public bool TryRegisterDeclaration( FlowScriptDeclaration declaration )
        {
            if ( IsDeclared( declaration.Identifier ) )
                return false;

            Declarations[declaration.Identifier.Text] = declaration;

            return true;
        }

        public bool TryGetDeclaration( FlowScriptIdentifier identifier, out FlowScriptDeclaration declaration )
        {
            if ( !Declarations.TryGetValue( identifier.Text, out declaration ) )
            {
                if ( Parent != null )
                {
                    return Parent.TryGetDeclaration( identifier, out declaration );
                }
                else
                {
                    return false;
                }
            }

            return true;
        }
    }
}
