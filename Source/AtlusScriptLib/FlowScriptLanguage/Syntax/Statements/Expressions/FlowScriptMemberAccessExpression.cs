using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptMemberAccessExpression : FlowScriptExpression, IFlowScriptOperator
    {
        public FlowScriptIdentifier Operand { get; set; }

        public FlowScriptIdentifier Member { get; set; }

        public int Precedence => 2;

        public FlowScriptMemberAccessExpression() : base( FlowScriptValueType.Unresolved )
        {
        }

        public override string ToString()
        {
            return $"{Operand}.{Member}";
        }
    }
}
