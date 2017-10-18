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
            string flowScriptSource =
                "void Main()" +
                "{" +
                "   test = 2;" +
                "}" +
                "" +
                "int test = 1;";

            var listener = new DebugLogListener();

            var parser = new FlowScriptCompilationUnitParser();
            parser.AddListener( listener );
            //Assert.IsTrue( parser.TryParse( File.ReadAllText(@"D:\Users\smart\Documents\Visual Studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptCompiler\Resources\Tests.flow"), out var compilationUnit ) );
            Assert.IsTrue( parser.TryParse( flowScriptSource, out var compilationUnit ) );
            //Assert.IsTrue( parser.TryParse( File.ReadAllText( @"D:\Users\smart\Documents\Visual Studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptCompiler\Resources\TestScript2.flow" ), out var compilationUnit ) );

            var resolver = new FlowScriptTypeResolver();
            resolver.AddListener( listener );
            Assert.IsTrue( resolver.TryResolveTypes( compilationUnit ) );

            var compiler = new FlowScriptCompiler( FlowScriptFormatVersion.Version3BigEndian );
            compiler.AddListener( listener );
            Assert.IsTrue( compiler.TryCompile( compilationUnit, out var flowScript ) );

            var messageScriptCompiler = new MessageScriptCompiler( MessageScriptLanguage.MessageScriptFormatVersion.Version1BigEndian, new Persona5Encoding() );
            Assert.IsTrue( messageScriptCompiler.TryCompile( File.ReadAllText( @"D:\Users\smart\Documents\Visual Studio 2017\Projects\AtlusScriptToolchain\Source\AtlusScriptCompiler\Resources\TestScript2.msg" ), out var messageScript ) );
            flowScript.MessageScript = messageScript;

            int fieldMajorId = 000;
            int fieldMinorId = 100;

            var archive = new PakToolArchiveFile();
            archive.Entries.Add( new PakToolArchiveEntry( $"init/fini_{fieldMajorId:D3}_{fieldMinorId:D3}.bf", ( MemoryStream )flowScript.ToStream() ) );
            archive.Save( $@"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\f{fieldMajorId:D3}_{fieldMinorId:D3}.pac" );

            var scriptBinary = flowScript.ToBinary();

            var disassembler = new FlowScriptBinaryDisassembler( $@"D:\Modding\Persona 5 EU\Game mods\TestLevel\mod\field\f{fieldMajorId:D3}_{fieldMinorId:D3}.flowasm" );
            disassembler.Disassemble( scriptBinary );
            disassembler.Dispose();

            Process.Start( @"D:\Modding\Persona 5 EU\Game mods\TestLevel\make_cpk_rpcs3.bat" );
        }

        void GenerateSelectBoss()
        {
            int selCount = 0;
            int counter = 0;
            foreach ( var procedure in FlowScriptBinary.FromFile( @"D:\Modding\Persona 5 EU\Main game\Extracted\data\field\script\boss.bf", FlowScriptBinaryFormatVersion.Version3BigEndian ).ProcedureLabelSection )
            {
                if ( counter == 0 )
                {
                    Debug.WriteLine( $"[sel SelectBoss{selCount++}]" );
                }

                Debug.WriteLine( $"[f 2 1]{procedure.Name}[e]" );
                counter++;

                if ( counter == 4 )
                {
                    Debug.WriteLine( "[f 2 1]Previous[e]" );
                    Debug.WriteLine( "[f 2 1]Next[e]" );
                    counter = 0;
                }
            }

            Debug.WriteLine( "int SelectBoss()" );
            Debug.WriteLine( "{" );
            Debug.WriteLine( "    while ( true )" );
            Debug.WriteLine( "    {" );
            Debug.WriteLine( "        int selection;" );

            int i = -1;
            int spaceCount = 8;
            int spacesPerTab = 4;
            void WriteTabbed(string value, int index)
            {
                for ( int j = 0; j < spaceCount + ( spacesPerTab * index ); j++ )
                {
                    Debug.Write( " " );
                }

                Debug.WriteLine( value );
            }

            void GenerateSelectBossSelectionRecursive()
            {
                int index = ++i;
                WriteTabbed( $"selection = SEL({index + 5});", index );
                WriteTabbed( "if ( selection == 4 )", index );
                WriteTabbed( "    continue;", index );
                WriteTabbed( "if ( selection == 5 )", index );
                WriteTabbed( "{", index );
                if ( i < selCount )
                    GenerateSelectBossSelectionRecursive();
                WriteTabbed( "}", index );
            }

            GenerateSelectBossSelectionRecursive();

            Debug.WriteLine( "    }" );
            Debug.WriteLine( "}" );
        }
    }
}