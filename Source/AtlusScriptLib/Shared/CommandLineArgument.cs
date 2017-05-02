using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Shared
{
    public class CommandLineArgument
    {
        public string Identifier { get; }

        public CommandLineArgument(string identifier)
        {
            Identifier = identifier;
        }
    }
}
