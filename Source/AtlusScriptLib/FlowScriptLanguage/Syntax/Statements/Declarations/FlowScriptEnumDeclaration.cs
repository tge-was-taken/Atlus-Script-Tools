using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax
{
    public class FlowScriptEnumDeclaration : FlowScriptDeclaration
    {
        public List<FlowScriptEnumValueDeclaration> Values { get; set; }

        public FlowScriptEnumDeclaration() : base( FlowScriptDeclarationType.Enum )
        {
            Values = new List< FlowScriptEnumValueDeclaration >();
        }

        public override string ToString()
        {
            return $"enum {Identifier} {{ ... }}";
        }
    }
}
