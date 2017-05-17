using System.Collections.Generic;

namespace AtlusScriptLib.Common.Syntax
{
    public class SyntaxTree
    {
        public List<SyntaxNode> Nodes { get; }

        public SyntaxTree()
        {
            Nodes = new List<SyntaxNode>();
        }

        public override string ToString()
        {
            return base.ToString();
        }
    }
}
