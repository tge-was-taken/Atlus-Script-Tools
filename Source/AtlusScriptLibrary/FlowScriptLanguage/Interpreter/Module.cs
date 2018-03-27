using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLibrary.FlowScriptLanguage.Interpreter
{
    public class Module
    {
        public Dictionary< int, Action< FlowScriptInterpreter > > Functions;
    }
}
