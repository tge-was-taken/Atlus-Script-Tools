using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Nodes
{
    public abstract class FlowScriptAstNode
    {
        public FlowScriptAstSourceInfo SourceInfo { get; internal set; }

        public override string ToString()
        {
            return SourceInfo.ToString();
        }
    }
}
