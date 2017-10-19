using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public abstract class FlowScriptBinaryExpression : FlowScriptExpression
    {
        public FlowScriptExpression Left { get; set; }

        public FlowScriptExpression Right { get; set; }

        protected FlowScriptBinaryExpression( FlowScriptValueType type ) : base( type )
        {
        }

        protected FlowScriptBinaryExpression( FlowScriptValueType type, FlowScriptExpression left, FlowScriptExpression right ) : this( type )
        {
            Left = left;
            Right = right;
        }
    }
}
