using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptCompoundStatement : FlowScriptStatement, IEnumerable<FlowScriptStatement>
    {
        public List<FlowScriptStatement> Statements { get; }

        public FlowScriptCompoundStatement()
        {
            Statements = new List<FlowScriptStatement>();
        }

        public FlowScriptCompoundStatement( params FlowScriptStatement[] statements )
        {
            Statements = statements.ToList();
        }

        public IEnumerator<FlowScriptStatement> GetEnumerator()
        {
            return ( ( IEnumerable<FlowScriptStatement> )Statements ).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ( ( IEnumerable<FlowScriptStatement> )Statements ).GetEnumerator();
        }

        public override string ToString()
        {
            return $"{{ {base.ToString()} }}";
        }
    }
}