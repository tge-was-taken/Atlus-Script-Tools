using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptUnaryExpression : FlowScriptExpression
    {
        public FlowScriptExpression Operand { get; set; }

        protected FlowScriptUnaryExpression( FlowScriptValueType type ) : base( type )
        {
        }

        protected FlowScriptUnaryExpression( FlowScriptValueType type, FlowScriptExpression operand ) : base( type )
        {
        }
    }
}
