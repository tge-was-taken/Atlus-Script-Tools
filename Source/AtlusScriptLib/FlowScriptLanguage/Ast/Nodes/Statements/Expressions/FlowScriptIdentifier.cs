﻿namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptIdentifier : FlowScriptExpression
    {
        public string Text { get; set; }

        public FlowScriptIdentifier() : base( FlowScriptValueType.Unresolved )
        {
        }

        public FlowScriptIdentifier( FlowScriptValueType type ) : base( type )
        {
        }

        public FlowScriptIdentifier( string text ) : base( FlowScriptValueType.Unresolved )
        {
            Text = text;
        }

        public FlowScriptIdentifier( FlowScriptValueType type, string text ) : base( FlowScriptValueType.Unresolved )
        {
            Text = text;
        }

        public override string ToString()
        {
            return Text;
        }
    }
}
