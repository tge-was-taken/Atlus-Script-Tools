using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib.FlowScriptLanguage.Ast;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;

namespace AtlusScriptLib.FlowScriptLanguage.Ast.Tests
{
    [TestClass()]
    public class FlowScriptAstParserTests
    {
        [TestMethod]
        public void TryParseTest()
        {
            string input =
                "string MyBeautifulProcedureDeclarationStatement( int arg0, int arg1, string arg2, float arg3 );";

            var parser = new FlowScriptAstParser();
            parser.AddListener( new TraceLogListener() );
            parser.TryParse( input, out var ast );
        }
    }
}