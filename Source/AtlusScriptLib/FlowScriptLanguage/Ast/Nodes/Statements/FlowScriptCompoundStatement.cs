using System.Collections;
using System.Collections.Generic;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public class FlowScriptCompoundStatement : FlowScriptStatement, IEnumerable<FlowScriptStatement>
    {
        public List<FlowScriptStatement> Statements { get; }

        public FlowScriptCompoundStatement()
        {
            Statements = new List<FlowScriptStatement>();
        }

        public IEnumerator<FlowScriptStatement> GetEnumerator()
        {
            return ( ( IEnumerable<FlowScriptStatement> )Statements ).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ( ( IEnumerable<FlowScriptStatement> )Statements ).GetEnumerator();
        }
    }
}