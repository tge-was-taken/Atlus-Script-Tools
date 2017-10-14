using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptExpression : FlowScriptStatement
    {
        public FlowScriptValueType ExpressionValueType { get; set; }

        protected FlowScriptExpression( FlowScriptValueType type )
        {
            ExpressionValueType = type;
        }
    }

    public abstract class FlowScriptCastExpression : FlowScriptExpression
    {
        protected FlowScriptCastExpression( FlowScriptValueType type ) : base( type )
        {
        }
    }
}