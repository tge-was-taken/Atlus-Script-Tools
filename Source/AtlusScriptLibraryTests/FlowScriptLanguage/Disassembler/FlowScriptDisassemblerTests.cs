using System.Collections.Generic;
using System.IO;
using System.Text;
using AtlusScriptLibrary.FlowScriptLanguage.BinaryModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLibrary.FlowScriptLanguage.Disassembler.Tests
{
    [TestClass]
    public class FlowScriptBinaryDisassemblerTests
    {
        private void DisassembleToFileTestBase( string path )
        {
            var script = FlowScriptBinary.FromFile( path, BinaryFormatVersion.Unknown );
            using ( var disassembler = new FlowScriptBinaryDisassembler( Path.ChangeExtension( path, "asm" ) ) )
                disassembler.Disassemble( script );
        }

        [TestMethod]
        public void DisassembleToFileTest_V1()
        {
            DisassembleToFileTestBase( "TestResources\\Version1.bf" );
        }

        [TestMethod]
        public void DisassembleToFileTest_V2()
        {
            DisassembleToFileTestBase( "TestResources\\Version2.bf" );
        }

        [TestMethod]
        public void DisassembleToFileTest_V3_BE()
        {
            DisassembleToFileTestBase( "TestResources\\Version3BigEndian.bf" );
        }

        [TestMethod]
        [Ignore]
        public void DisassembleToFileTest_Batch()
        {
            foreach ( var path in Directory.EnumerateFiles( "TestResources\\Batch\\", "*.bf" ) )
            {
                DisassembleToFileTestBase( path );
            }
        }

        [TestMethod]
        public void DisassembleTest()
        {
            var script = FlowScriptBinary.FromFile( "TestResources\\Version1.bf" );
            using ( var disassembler = new FlowScriptBinaryDisassembler( new StringWriter() ) )
                disassembler.Disassemble( script );
        }

        [TestMethod]
        public void DisassembleInstructionWithIntOperandTest()
        {
            var opcode = Opcode.PUSHI;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithIntOperand( new BinaryInstruction { Opcode = opcode }, new BinaryInstruction { OperandInt = 42 } );
            var expectedDisassemblyText = "PUSHI	0000002A";
            Assert.AreEqual( expectedDisassemblyText, disassemblyText );
        }

        [TestMethod]
        public void DisassembleInstructionWithFloatOperandTest()
        {
            var opcode = Opcode.PUSHF;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithFloatOperand( new BinaryInstruction { Opcode = opcode }, new BinaryInstruction { OperandFloat = 42.42f } );
            var expectedDisassemblyText = "PUSHF		42.42f";
            Assert.AreEqual( expectedDisassemblyText, disassemblyText );
        }

        [TestMethod]
        public void DisassembleInstructionWithShortOperandTest()
        {
            var opcode = Opcode.PUSHIS;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithShortOperand( new BinaryInstruction { Opcode = opcode, OperandShort = 42 } );
            var expectedDisassemblyText = "PUSHIS	002A";
            Assert.AreEqual( expectedDisassemblyText, disassemblyText );
        }

        [TestMethod]
        public void DisassembleInstructionWithStringReferenceOperandTest()
        {
            var opcode = Opcode.PUSHSTR;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithStringReferenceOperand(
                new BinaryInstruction { Opcode = opcode, OperandShort = 0 },
                Encoding.ASCII.GetBytes( "foobar" )
                );

            var expectedDisassemblyText = "PUSHSTR	\"foobar\"";
            Assert.AreEqual( expectedDisassemblyText, disassemblyText );
        }

        [TestMethod]
        public void DisassembleInstructionWithLabelReferenceOperandTest()
        {
            string labelName = "foobar";
            var opcode = Opcode.PROC;
            var expectedDisassemblyText = $"PROC		{labelName}";
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithLabelReferenceOperand(
                new BinaryInstruction { Opcode = opcode, OperandShort = 0 },
                new List<BinaryLabel> { new BinaryLabel { InstructionIndex = 0, Name = labelName, Reserved = 0 } }
                );

            Assert.AreEqual( expectedDisassemblyText, disassemblyText );
        }

        [TestMethod]
        public void DisassembleInstructionWithNoOperandTest()
        {
            var opcode = Opcode.ADD;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithNoOperand( new BinaryInstruction { Opcode = opcode } );
            var expectedDisassemblyText = "ADD";

            Assert.AreEqual( expectedDisassemblyText, disassemblyText );
        }

        [TestMethod]
        public void DisassembleInstructionWithCommReferenceTest()
        {
            var opcode = Opcode.COMM;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithCommReferenceOperand( new BinaryInstruction { Opcode = opcode, OperandShort = 0 } );
            var expectedDisassemblyText = "COMM		0000";
            Assert.AreEqual( expectedDisassemblyText, disassemblyText );
        }
    }
}