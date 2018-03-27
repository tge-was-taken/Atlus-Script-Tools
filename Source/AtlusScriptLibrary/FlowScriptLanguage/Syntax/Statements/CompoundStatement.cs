using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.FlowScriptLanguage.Syntax
{
    public class CompoundStatement : Statement, IEnumerable<Statement>
    {
        public List<Statement> Statements { get; }

        public CompoundStatement()
        {
            Statements = new List<Statement>();
        }

        public CompoundStatement( List<Statement> statements )
        {
            Statements = statements;
        }

        public CompoundStatement( params Statement[] statements )
        {
            Statements = statements.ToList();
        }

        public IEnumerator<Statement> GetEnumerator()
        {
            return ( ( IEnumerable<Statement> )Statements ).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ( ( IEnumerable<Statement> )Statements ).GetEnumerator();
        }

        public override string ToString()
        {
            return $"{{ {base.ToString()} }}";
        }
    }
}