using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Compiler;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Parser;
using AtlusScriptLib.FlowScriptLanguage.Compiler.Processing;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax.Tests
{
    [TestClass()]
    public class FlowScriptSyntaxParserTests
    {
        [TestMethod]
        public void TryParseTest()
        {
            string input =
                "int proc()" +
                "{" +
                "   int a = 0;" +
                "   a = a + 1;" +
                "   a = a - 1;" +
                "   a = a * 1;" +
                "   a = a / 1;" +
                "   a = -a;" +
                "   /*a = ~a;*/" +
                "   bool b = a == 0 || ( a == 1 && a == 1 );" +
                "   b = b == false;" +
                "   b = b != true;" +
                "   bool c = a > 0;" +
                "   bool d = a >= 0;" +
                "   bool e = a < 0;" +
                "   bool f = a <= 0;" +
                "   goto label;" +
                "label:" +
                "   return a;" +
                "}";

            /*
            */

            var listener = new DebugLogListener();

            var parser = new FlowScriptCompilationUnitParser();
            parser.AddListener( listener );
            Assert.IsTrue( parser.TryParse( input, out var compilationUnit ) );

            var resolver = new FlowScriptTypeResolver();
            resolver.AddListener( listener );
            Assert.IsTrue( resolver.TryResolveTypes( compilationUnit ) );

            var compiler = new FlowScriptCompiler( FlowScriptFormatVersion.Version3BigEndian );
            compiler.AddListener( listener );
            Assert.IsTrue( compiler.TryCompile( compilationUnit, out var flowScript ) );
        }
    }
}