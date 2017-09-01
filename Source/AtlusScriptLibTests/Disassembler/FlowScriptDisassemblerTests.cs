using System.Collections.Generic;
using System.IO;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib.Disassemblers;
using System;
using AtlusScriptLib.BinaryModel;

namespace AtlusScriptLib.Disassembler.Tests
{
    [TestClass()]
    public class FlowScriptBinaryDisassemblerTests
    {
        private void DisassembleToFileTestBase(string path)
        {
            var script = FlowScriptBinary.FromFile(path, FlowScriptBinaryFormatVersion.Unknown);
            using (var disassembler = new FlowScriptBinaryDisassembler(Path.ChangeExtension(path, "asm")))
                disassembler.Disassemble(script);
        }

        [TestMethod()]
        public void DisassembleToFileTest_V1()
        {
            DisassembleToFileTestBase("TestResources\\Version1.bf");
        }

        [TestMethod()]
        public void DisassembleToFileTest_V2()
        {
            DisassembleToFileTestBase("TestResources\\Version2.bf");
        }

        [TestMethod()]
        public void DisassembleToFileTest_V3_BE()
        {
            DisassembleToFileTestBase("TestResources\\Version3BigEndian.bf");
        }

        [TestMethod()]
        [Ignore]
        public void DisassembleToFileTest_Batch()
        {
            foreach (var path in Directory.EnumerateFiles("TestResources\\Batch\\", "*.bf"))
            {
                DisassembleToFileTestBase(path);
            }
        }

        [TestMethod()]
        public void DisassembleTest()
        {
            var script = FlowScriptBinary.FromFile("TestResources\\Version1.bf");
            var builder = new StringBuilder();
            using (var disassembler = new FlowScriptBinaryDisassembler(builder))
                disassembler.Disassemble(script);
        }

        [TestMethod()]
        public void DisassembleInstructionWithIntOperandTest()
        {
            var opcode = FlowScriptOpcode.PUSHI;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithIntOperand(new FlowScriptBinaryInstruction() { Opcode = opcode }, new FlowScriptBinaryInstruction() { OperandInt = 42 });
            var expectedDisassemblyText = "PUSHI 42";
            Assert.AreEqual(expectedDisassemblyText, disassemblyText);
        }

        [TestMethod()]
        public void DisassembleInstructionWithFloatOperandTest()
        {
            var opcode = FlowScriptOpcode.PUSHF;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithFloatOperand(new FlowScriptBinaryInstruction() { Opcode = opcode }, new FlowScriptBinaryInstruction() { OperandFloat = 42.42f });
            var expectedDisassemblyText = "PUSHF 42.42f";
            Assert.AreEqual(expectedDisassemblyText, disassemblyText);
        }

        [TestMethod()]
        public void DisassembleInstructionWithShortOperandTest()
        {
            var opcode = FlowScriptOpcode.PUSHIS;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithShortOperand(new FlowScriptBinaryInstruction() { Opcode = opcode, OperandShort = 42 });
            var expectedDisassemblyText = "PUSHIS 42";
            Assert.AreEqual(expectedDisassemblyText, disassemblyText);
        }

        [TestMethod()]
        public void DisassembleInstructionWithStringReferenceOperandTest()
        {
            var opcode = FlowScriptOpcode.PUSHSTR;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithStringReferenceOperand(
                new FlowScriptBinaryInstruction() { Opcode = opcode, OperandShort = 0 },
                Encoding.ASCII.GetBytes("foobar")
                );

            var expectedDisassemblyText = "PUSHSTR \"foobar\"";
            Assert.AreEqual(expectedDisassemblyText, disassemblyText);
        }

        [TestMethod()]
        public void DisassembleInstructionWithLabelReferenceOperandTest()
        {
            string labelName = "foobar";
            var opcode = FlowScriptOpcode.PROC;
            var expectedDisassemblyText = $"PROC {labelName}";
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithLabelReferenceOperand(
                new FlowScriptBinaryInstruction() { Opcode = opcode, OperandShort = 0 },
                new List<FlowScriptBinaryLabel>() { new FlowScriptBinaryLabel() {  InstructionIndex = 0, Name = labelName, Reserved = 0 } }
                );          

            Assert.AreEqual(expectedDisassemblyText, disassemblyText);
        }

        [TestMethod()]
        public void DisassembleInstructionWithNoOperandTest()
        {
            var opcode = FlowScriptOpcode.ADD;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithNoOperand(new FlowScriptBinaryInstruction() { Opcode = opcode });
            var expectedDisassemblyText = "ADD";

            Assert.AreEqual(expectedDisassemblyText, disassemblyText);
        }

        [TestMethod()]
        public void DisassembleInstructionWithCommReferenceTest()
        {
            var opcode = FlowScriptOpcode.COMM;
            var disassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithCommReferenceOperand(new FlowScriptBinaryInstruction() { Opcode = opcode, OperandShort = 0 });
            var expectedDisassemblyText = "COMM 0";
            Assert.AreEqual(expectedDisassemblyText, disassemblyText);
        }
    }
}