using System.Collections.Generic;
using AtlusScriptLibrary.FlowScriptLanguage.Syntax;

namespace AtlusScriptLibrary.FlowScriptLanguage.Decompiler
{
    public class EvaluatedScope
    {
        public EvaluatedScope Parent { get; set; }

        public Dictionary<int, VariableDeclaration> StaticIntVariables { get; set; }

        public Dictionary<int, VariableDeclaration> StaticFloatVariables { get; set; }

        public Dictionary<int, VariableDeclaration> LocalIntVariables { get; set; }

        public Dictionary<int, VariableDeclaration> LocalFloatVariables { get; set; }

        public Dictionary<string, VariableDeclaration> Variables { get; set; }

        public EvaluatedScope( EvaluatedScope parent )
        {
            Parent = parent;
            StaticIntVariables = new Dictionary<int, VariableDeclaration>();
            StaticFloatVariables = new Dictionary<int, VariableDeclaration>();
            LocalIntVariables = new Dictionary<int, VariableDeclaration>();
            LocalFloatVariables = new Dictionary<int, VariableDeclaration>();
            Variables = new Dictionary<string, VariableDeclaration>();
        }

        public bool TryGetGlobalIntVariable( int index, out VariableDeclaration declaration )
        {
            if ( !StaticIntVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetGlobalIntVariable( index, out declaration );
                return false;
            }

            return true;
        }

        public bool TryGetGlobalFloatVariable( int index, out VariableDeclaration declaration )
        {
            if ( !StaticFloatVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetGlobalFloatVariable( index, out declaration );
                return false;
            }

            return true;
        }

        public bool TryGetLocalIntVariable( int index, out VariableDeclaration declaration )
        {
            if ( !LocalIntVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetLocalIntVariable( index, out declaration );
                return false;
            }

            return true;
        }

        public bool TryGetLocalFloatVariable( int index, out VariableDeclaration declaration )
        {
            if ( !LocalFloatVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetLocalFloatVariable( index, out declaration );
                return false;
            }

            return true;
        }

        public bool TryDeclareGlobalIntVariable( int index, VariableDeclaration declaration )
        {
            if ( TryGetGlobalIntVariable( index, out var _ ) )
                return false;

            StaticIntVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }

        public bool TryDeclareGlobalFloatVariable( int index, VariableDeclaration declaration )
        {
            if ( TryGetGlobalFloatVariable( index, out var _ ) )
                return false;

            StaticFloatVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }

        public bool TryDeclareLocalIntVariable( int index, VariableDeclaration declaration )
        {
            if ( TryGetLocalIntVariable( index, out var _ ) )
                return false;

            LocalIntVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }

        public bool TryDeclareLocalFloatVariable( int index, VariableDeclaration declaration )
        {
            if ( TryGetLocalFloatVariable( index, out var _ ) )
                return false;

            LocalFloatVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }
    }
}
