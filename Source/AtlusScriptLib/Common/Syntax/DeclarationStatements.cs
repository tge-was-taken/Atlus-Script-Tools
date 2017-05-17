using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Syntax
{
    public abstract class Declaration : Statement
    {
        public Identifier Identifier { get; }

        public Declaration(Identifier identifier)
        {
            Identifier = identifier;
        }

        public override string ToString()
        {
            return Identifier.Name;
        }
    }
}
