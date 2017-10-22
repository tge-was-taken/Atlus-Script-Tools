using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.FlowScriptLanguage.Syntax;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptEvaluatedScope
    {
        public FlowScriptEvaluatedScope Parent { get; set; }

        public Dictionary<int, FlowScriptVariableDeclaration> StaticIntVariables { get; set; }

        public Dictionary<int, FlowScriptVariableDeclaration> StaticFloatVariables { get; set; }

        public Dictionary<int, FlowScriptVariableDeclaration> LocalIntVariables { get; set; }

        public Dictionary<int, FlowScriptVariableDeclaration> LocalFloatVariables { get; set; }

        public Dictionary<string, FlowScriptVariableDeclaration> Variables { get; set; }

        public FlowScriptEvaluatedScope( FlowScriptEvaluatedScope parent )
        {
            Parent = parent;
            StaticIntVariables = new Dictionary<int, FlowScriptVariableDeclaration>();
            StaticFloatVariables = new Dictionary<int, FlowScriptVariableDeclaration>();
            LocalIntVariables = new Dictionary<int, FlowScriptVariableDeclaration>();
            LocalFloatVariables = new Dictionary<int, FlowScriptVariableDeclaration>();
            Variables = new Dictionary<string, FlowScriptVariableDeclaration>();
        }

        public bool TryGetStaticIntVariable( int index, out FlowScriptVariableDeclaration declaration )
        {
            if ( !StaticIntVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetStaticIntVariable( index, out declaration );
                else
                    return false;
            }

            return true;
        }

        public bool TryGetStaticFloatVariable( int index, out FlowScriptVariableDeclaration declaration )
        {
            if ( !StaticFloatVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetStaticFloatVariable( index, out declaration );
                else
                    return false;
            }

            return true;
        }

        public bool TryGetLocalIntVariable( int index, out FlowScriptVariableDeclaration declaration )
        {
            if ( !LocalIntVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetLocalIntVariable( index, out declaration );
                else
                    return false;
            }

            return true;
        }

        public bool TryGetLocalFloatVariable( int index, out FlowScriptVariableDeclaration declaration )
        {
            if ( !LocalFloatVariables.TryGetValue( index, out declaration ) )
            {
                if ( Parent != null )
                    return Parent.TryGetLocalFloatVariable( index, out declaration );
                else
                    return false;
            }

            return true;
        }

        public bool TryDeclareStaticIntVariable( int index, FlowScriptVariableDeclaration declaration )
        {
            if ( TryGetStaticIntVariable( index, out var _ ) )
                return false;

            StaticIntVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }

        public bool TryDeclareStaticFloatVariable( int index, FlowScriptVariableDeclaration declaration )
        {
            if ( TryGetStaticFloatVariable( index, out var _ ) )
                return false;

            StaticFloatVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }

        public bool TryDeclareLocalIntVariable( int index, FlowScriptVariableDeclaration declaration )
        {
            if ( TryGetLocalIntVariable( index, out var _ ) )
                return false;

            LocalIntVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }

        public bool TryDeclareLocalFloatVariable( int index, FlowScriptVariableDeclaration declaration )
        {
            if ( TryGetLocalFloatVariable( index, out var _ ) )
                return false;

            LocalFloatVariables[index] = declaration;
            Variables[declaration.Identifier.Text] = declaration;
            return true;
        }
    }
}
