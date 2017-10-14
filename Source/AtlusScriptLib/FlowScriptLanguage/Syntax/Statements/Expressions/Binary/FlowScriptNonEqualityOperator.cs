using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptNonEqualityOperator : FlowScriptBinaryExpression, IFlowScriptOperator
    {
        public int Precedence => 9;

        public FlowScriptNonEqualityOperator() : base( FlowScriptValueType.Bool )
        {
        }

        public override string ToString()
        {
            return $"{Left} != {Right}";
        }
    }
}
