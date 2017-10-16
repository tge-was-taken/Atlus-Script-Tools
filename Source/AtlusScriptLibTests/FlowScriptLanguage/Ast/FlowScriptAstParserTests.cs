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
using System.IO;
using AtlusLibSharp.FileSystems.PAKToolArchive;

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

            input =
                "function( 0x0002 ) void PUT( int param0 );" +
                "function( 0x0003 ) void PUTS( string str );" +
                "function( 0x0004 ) void PUTF(float param0);" +
                "" +
                "void f000_100_init()" +
                "{" +
                "   PUT( 1024 );" +
                "   PUTS( \"Hello Persona 5!!\" );" +
                "   PUTF( 1000.1234f );" +
                "}";

            var listener = new DebugLogListener();

            var parser = new FlowScriptCompilationUnitParser();
            parser.AddListener( listener );
            Assert.IsTrue( parser.TryParse( File.ReadAllText(@"D:\Users\smart\Documents\Visual Studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptCompiler\Resources\Tests.flow"), out var compilationUnit ) );
            //Assert.IsTrue( parser.TryParse( input, out var compilationUnit ) );

            var resolver = new FlowScriptTypeResolver();
            resolver.AddListener( listener );
            Assert.IsTrue( resolver.TryResolveTypes( compilationUnit ) );

            var compiler = new FlowScriptCompiler( FlowScriptFormatVersion.Version3BigEndian );
            compiler.AddListener( listener );
            Assert.IsTrue( compiler.TryCompile( compilationUnit, out var flowScript ) );

            int fieldMajorId = 000;
            int fieldMinorId = 100;

            var archive = new PakToolArchiveFile();
            archive.Entries.Add( new PakToolArchiveEntry( $"init/fini_{fieldMajorId:D3}_{fieldMinorId:D3}.bf", ( MemoryStream )flowScript.ToStream() ) );
            archive.Save( $@"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\f{fieldMajorId:D3}_{fieldMinorId:D3}.pac" );

            var scriptBinary = flowScript.ToBinary();
        }
    }
}