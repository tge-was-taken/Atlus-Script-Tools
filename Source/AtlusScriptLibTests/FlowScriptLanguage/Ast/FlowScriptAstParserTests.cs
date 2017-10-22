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
using AtlusScriptLib.FlowScriptLanguage.Disassembler;
using System.Diagnostics;
using AtlusScriptLib.MessageScriptLanguage.Compiler;
using AtlusScriptLib.Common.Text.Encodings;
using AtlusScriptLib.FlowScriptLanguage.BinaryModel;
using AtlusScriptLib.FlowScriptLanguage.Decompiler;
using AtlusScriptLib.FlowScriptLanguage.FunctionDatabase;

namespace AtlusScriptLib.FlowScriptLanguage.Syntax.Tests
{
    [TestClass()]
    public class FlowScriptSyntaxParserTests
    {
        [TestMethod]
        public void TryParseTest()
        {
            // FLD_GET_SCRIPT_TIMING returns a value ranging from 0 to 4 indicating the loading phase
            // without [f 2 1] the text doesn't scroll
            // options without any text won't be displayed
            var listener = new DebugLogListener();

            string flowScriptSource =
                "void Main()" +
                "{" +
                "   int a;" +
                "   if ( true )" +
                "   {" +
                "       a = 1;" +
                "   }" +
                "   else" +
                "   {" +
                "       a = 0;" +
                "   }" +
                "}";

            FlowScript flowScript;

            var flowScriptCompiler = new FlowScriptCompiler( FlowScriptFormatVersion.Version3BigEndian );
            flowScriptCompiler.AddListener( listener );
            flowScriptCompiler.EnableProcedureTracing = false;
            flowScriptCompiler.EnableProcedureCallTracing = false;
            flowScriptCompiler.EnableFunctionCallTracing = false;
            flowScriptCompiler.EnableStackTracing = false;
            flowScriptCompiler.EnableStackCookie = false;

            //Assert.IsTrue( flowScriptCompiler.TryCompile( File.Open( @"D:\Users\smart\Documents\Visual Studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptCompiler\Resources\TestScript2.flow", FileMode.Open ), out flowScript ) );
            //Assert.IsTrue( flowScriptCompiler.TryCompile( flowScriptSource, out var flowScript ) );
            //Assert.IsTrue( flowScriptCompiler.TryCompile( File.Open( @"D:\Users\smart\Documents\Visual Studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptCompiler\Resources\Tests.flow", FileMode.Open ), out var flowScript ) );

            var flowScriptDecompiler = new FlowScriptDecompiler();
            flowScriptDecompiler.AddListener( listener );
            flowScriptDecompiler.FunctionDatabase = Persona5FunctionDatabase.Instance;
            //Assert.IsTrue( flowScriptDecompiler.TryDecompile( flowScript, out var compilationUnit ) );
            Assert.IsTrue( flowScriptDecompiler.TryDecompile( FlowScript.FromFile( @"D:\Modding\Persona 5 EU\Main game\Extracted\data\field\script\boss.bf" ), out var compilationUnit ) );

            var flowScriptCompilationUnitWriter = new FlowScriptCompilationUnitWriter();
            flowScriptCompilationUnitWriter.WriteToFile( compilationUnit, "output.flow" );

            Assert.IsTrue( flowScriptCompiler.TryCompile( File.OpenRead( "output.flow" ), out flowScript ) );

            int fieldMajorId = 000;
            int fieldMinorId = 100;

            var archive = new PakToolArchiveFile();
            archive.Entries.Add( new PakToolArchiveEntry( $"init/fini_{fieldMajorId:D3}_{fieldMinorId:D3}.bf", ( MemoryStream )flowScript.ToStream() ) );
            archive.Save( $@"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\f{fieldMajorId:D3}_{fieldMinorId:D3}.pac" );

            var flowScriptBinary = flowScript.ToBinary();
            var flowScriptDiassembler = new FlowScriptBinaryDisassembler( $@"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\f{fieldMajorId:D3}_{fieldMinorId:D3}.flowasm" );
            flowScriptDiassembler.Disassemble( flowScriptBinary );
            flowScriptDiassembler.Dispose();

            Process.Start( @"D:\Modding\Persona 5 EU\Game mods\TestLevel\make_cpk_rpcs3.bat" );
        }
    }
}