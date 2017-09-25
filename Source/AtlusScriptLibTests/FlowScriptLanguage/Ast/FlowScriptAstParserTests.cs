using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Common.Logging;
using AtlusScriptLib.FlowScriptLanguage.Compiler;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax.Tests
{
    [TestClass()]
    public class FlowScriptSyntaxParserTests
    {
        [TestMethod]
        public void TryParseTest()
        {
            //// Procedure declaration - works
            //string input =
            //    "string MyBeautifulProcedureDeclarationStatement( int arg0, int arg1, string arg2, float arg3 );";

            // Variable declaration

            string input =
                "int func( 0x0011 ) RND( int max );\n" +
                "void func( 0x005c ) BGM( int bgmId );\n" +
                "\n" +
                "void f000_002_init()\n" +
                "{\n" +
                "   int bgmId = RND( 300 );\n" +
                "   BGM( bgmId );\n" +
                "}\n";

            var listener = new DebugLogListener();

            var parser = new FlowScriptSyntaxParser();
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