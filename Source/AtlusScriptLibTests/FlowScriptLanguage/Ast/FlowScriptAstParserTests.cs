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
//using AtlusLibSharp.FileSystems.PAKToolArchive;
using AtlusScriptLib.FlowScriptLanguage.Disassembler;
using System.Diagnostics;
using AtlusLibSharp.FileSystems.PAKToolArchive;
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

            // TODO: implement custom types

            var listener = new DebugLogListener();

            string flowScriptSource =
                "void Main()" +
                "{" +
                "   for ( int i = 0; i < 22; i = i + 1 )" +
                "   {" +
                "   }" +
                "}";

            FlowScript flowScript;

            var flowScriptCompiler = new FlowScriptCompiler( FlowScriptFormatVersion.Version3BigEndian );
            flowScriptCompiler.AddListener( listener );
            flowScriptCompiler.EnableProcedureTracing = true;
            flowScriptCompiler.EnableProcedureCallTracing = true;
            flowScriptCompiler.EnableFunctionCallTracing = true;
            flowScriptCompiler.EnableStackCookie = false;

            var flowScriptDecompiler = new FlowScriptDecompiler();
            flowScriptDecompiler.AddListener( listener );
            flowScriptDecompiler.FunctionDatabase = Persona5FunctionDatabase.Instance;

            var flowScriptDiassembler = new FlowScriptBinaryDisassembler( $@"test.flow.asm" );

            //Assert.IsTrue( flowScriptCompiler.TryCompile( File.OpenRead( "test.flow" ), out flowScript ) );
            //Assert.IsTrue( flowScriptDecompiler.TryDecompile( flowScript, "test.flow.decompiled" ) );
            //Assert.IsTrue( flowScriptDecompiler.TryDecompile( FlowScript.FromFile( @"D:\Modding\Persona 5 EU\Main game\Extracted\ps3\field\fldPack.pac.etc_field.bf" ), "field.flow" ) );

            //var flowScriptBinary = flowScript.ToBinary();
            //flowScriptDiassembler.Disassemble( flowScriptBinary );


            //Assert.IsTrue( flowScriptCompiler.TryCompile( File.Open(@"..\..\..\Source\AtlusScriptCompiler\Resources\TestScript2.flow", FileMode.Open ), out flowScript ) );
            //Assert.IsTrue( flowScriptCompiler.TryCompile( flowScriptSource, out flowScript ) );
            //Assert.IsTrue( flowScriptCompiler.TryCompile( File.Open( @"D:\Users\smart\Documents\Visual Studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptCompiler\Resources\Tests.flow", FileMode.Open ), out flowScript ) );
            Assert.IsTrue( flowScriptCompiler.TryCompile( File.Open( @"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\field.flow", FileMode.Open ), out flowScript ) );

            flowScriptDiassembler.Disassemble( flowScript.ToBinary() );
            flowScriptDiassembler.Dispose();



            /*
            var fldPack = new PakToolArchiveFile( @"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\fldPack.pac" );
            flowScript = FlowScript.FromStream(
                new MemoryStream( fldPack.Entries.Single( x => x.Name == "etc/field.bf" ).Data )
            );
            */

            //Assert.IsTrue( flowScriptDecompiler.TryDecompile( flowScript, "output.flow" ) );          
            //Assert.IsTrue( flowScriptCompiler.TryCompile( File.OpenRead( "output.flow" ), out flowScript ) );

            /*
            const int fieldMajorId = 000;
            const int fieldMinorId = 002;
            //const int fieldMinorId = 100;

            var archive = new PakToolArchiveFile();
            archive.Entries.Add( new PakToolArchiveEntry( $"init/fini_{fieldMajorId:D3}_{fieldMinorId:D3}.bf", ( MemoryStream )flowScript.ToStream() ) );
            archive.Save( $@"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\f{fieldMajorId:D3}_{fieldMinorId:D3}.pac" );

            var flowScriptBinary = flowScript.ToBinary();
            var flowScriptDiassembler = new FlowScriptBinaryDisassembler( $@"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\f{fieldMajorId:D3}_{fieldMinorId:D3}.flowasm" );
            flowScriptDiassembler.Disassemble( flowScriptBinary );
            flowScriptDiassembler.Dispose();
            */

            /*
            var archive = new PakToolArchiveFile( @"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\fldPack.pac" );
            var entry = archive.Entries.Single( x => x.Name == "etc/field.bf" );
            entry.Data = ( ( MemoryStream ) flowScript.ToStream() ).ToArray();

            archive.Save( @"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\fldPack.pac" );

            Process.Start( @"D:\Modding\Persona 5 EU\Game mods\TestLevel\make_cpk_rpcs3.bat" );
            */
            //OutputBothDisassemblies( @"D:\Modding\Persona 5 EU\Main game\Extracted\data\event\e800\e800\e800_021.bf", false );

            //flowScriptDiassembler.Dispose();
        }

        static void OutputBothDisassemblies( string path, bool isSource )
        {
            FlowScript flowScript;

            if ( isSource )
            {
                flowScript = Compile( path );
            }
            else
            {
                flowScript = FlowScript.FromFile( path );
            }

            Dissassemble( flowScript, "original_disassembly.flowasm" );

            var flowScriptDecompiler = new FlowScriptDecompiler();
            flowScriptDecompiler.AddListener( new DebugLogListener() );
            flowScriptDecompiler.FunctionDatabase = Persona5FunctionDatabase.Instance;
            Assert.IsTrue( flowScriptDecompiler.TryDecompile( flowScript, out var compilationUnit ) );

            var flowScriptCompilationUnitWriter = new FlowScriptCompilationUnitWriter();
            flowScriptCompilationUnitWriter.WriteToFile( compilationUnit, "original_decompiled.flow" );

            var newFlowScript = Compile( File.ReadAllText( "original_decompiled.flow" ) );
            Dissassemble( newFlowScript, "recompiled_disassembly.flowasm" );
        }

        static FlowScript Compile( string source )
        {
            var flowScriptCompiler = new FlowScriptCompiler( FlowScriptFormatVersion.Version3BigEndian );
            flowScriptCompiler.AddListener( new DebugLogListener() );
            flowScriptCompiler.EnableProcedureTracing = false;
            flowScriptCompiler.EnableProcedureCallTracing = false;
            flowScriptCompiler.EnableFunctionCallTracing = false;
            flowScriptCompiler.EnableStackCookie = false;
            Assert.IsTrue( flowScriptCompiler.TryCompile( source, out var flowScript ) );
            return flowScript;
        }

        static void Dissassemble( FlowScript flowScript, string path )
        {
            var flowScriptBinary = flowScript.ToBinary();
            var flowScriptDiassembler = new FlowScriptBinaryDisassembler( path );
            flowScriptDiassembler.Disassemble( flowScriptBinary );
            flowScriptDiassembler.Dispose();
        }
    }
}