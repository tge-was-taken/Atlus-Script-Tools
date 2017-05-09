using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib.Shared.Syntax
{
    // Argument list
    public class FunctionArgumentList : SyntaxNode, IEnumerable<Statement>
    {
        public List<Statement> Arguments { get; }

        public FunctionArgumentList()
        {
            Arguments = new List<Statement>();
        }

        public FunctionArgumentList(List<Statement> arguments)
        {
            Arguments = arguments;
        }

        public FunctionArgumentList(params Statement[] arguments)
        {
            Arguments = arguments.ToList();
        }

        public override string ToString()
        {
            var argsString = string.Empty;

            bool isFirst = true;
            foreach (var item in Arguments)
            {
                if (!isFirst)
                    argsString += ", ";
                else
                    isFirst = false;

                argsString += item.ToString();
            }

            return $"({argsString})";
        }

        public IEnumerator<Statement> GetEnumerator()
        {
            return ((IEnumerable<Statement>)Arguments).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ((IEnumerable<Statement>)Arguments).GetEnumerator();
        }
    }
}
