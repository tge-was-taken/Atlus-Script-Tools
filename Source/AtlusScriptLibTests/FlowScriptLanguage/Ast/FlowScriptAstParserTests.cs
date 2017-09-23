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

            var parser = new FlowScriptAstParser();
            parser.AddListener( new TraceLogListener() );
            Assert.IsTrue( parser.TryParse( input, out var compilationUnit ) );

            var resolver = new FlowScriptAstTypeResolver();
            resolver.AddListener( new TraceLogListener() );
            Assert.IsTrue( resolver.TryResolveTypes( compilationUnit ) );
        }
    }
}