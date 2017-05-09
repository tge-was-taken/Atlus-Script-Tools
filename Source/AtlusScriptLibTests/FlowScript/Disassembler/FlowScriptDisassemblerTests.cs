using System.Collections.Generic;
using System.IO;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLib.FlowScript.Disassembler.Tests
{
    [TestClass()]
    public class FlowScriptBinaryDisassemblerTests
    {
        public FlowScriptBinaryDisassembler Disassembler;
        public FlowScriptBinary Script;
        public string DisassemblyText;
        public string ExpectedDisassemblyText;
        public FlowScriptBinaryOpcode Opcode;

        private void DisassembleToFileTestBase(string path)
        {
            Assert.AreEqual(FlowScriptBinaryLoadResult.OK, FlowScriptBinary.LoadFromFile(path, FlowScriptBinaryVersion.Unknown, out Script));
            Disassembler = new FlowScriptBinaryDisassembler(Path.ChangeExtension(path, "flwasm"));
            Disassembler.Disassemble(Script);
        }

        [TestMethod()]
        public void DisassembleToFileTest_V1()
        {
            DisassembleToFileTestBase("TestResources\\V1.bf");
        }

        [TestMethod()]
        public void DisassembleToFileTest_V2()
        {
            DisassembleToFileTestBase("TestResources\\V2.bf");
        }

        [TestMethod()]
        public void DisassembleToFileTest_V3_BE()
        {
            DisassembleToFileTestBase("TestResources\\V3_BE.bf");
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
            FlowScriptBinary.LoadFromFile("TestResources\\V1.bf", out FlowScriptBinary script);
            var builder = new StringBuilder();
            Disassembler = new FlowScriptBinaryDisassembler(builder);
            Disassembler.Disassemble(script);
        }

        [TestMethod()]
        public void DisassembleInstructionWithIntOperandTest()
        {
            Opcode = FlowScriptBinaryOpcode.PUSHI;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithIntOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode }, new FlowScriptBinaryInstruction() { OperandInt = 42 });
            ExpectedDisassemblyText = "PUSHI 42";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithFloatOperandTest()
        {
            Opcode = FlowScriptBinaryOpcode.PUSHF;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithFloatOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode }, new FlowScriptBinaryInstruction() { OperandFloat = 42.42f });
            ExpectedDisassemblyText = "PUSHF 42.42f";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithShortOperandTest()
        {
            Opcode = FlowScriptBinaryOpcode.PUSHIS;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithShortOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 42 });
            ExpectedDisassemblyText = "PUSHIS 42";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithStringReferenceOperandTest()
        {
            Opcode = FlowScriptBinaryOpcode.PUSHSTR;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithStringReferenceOperand(
                new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 0 },
                new Dictionary<int, string>() { { 0, "foobar" } }
                );

            ExpectedDisassemblyText = "PUSHSTR \"foobar\"";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithLabelReferenceOperandTest()
        {
            string labelName = "foobar";
            Opcode = FlowScriptBinaryOpcode.PROC;
            ExpectedDisassemblyText = $"PROC {labelName}";
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithLabelReferenceOperand(
                new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 0 },
                new List<FlowScriptBinaryLabel>() { new FlowScriptBinaryLabel() {  Name = labelName, Offset = 0, Reserved = 0} }
                );          

            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithNoOperandTest()
        {
            Opcode = FlowScriptBinaryOpcode.ADD;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithNoOperand(new FlowScriptBinaryInstruction() { Opcode = FlowScriptBinaryOpcode.ADD });
            ExpectedDisassemblyText = "ADD";

            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithCommReferenceTest()
        {
            Opcode = FlowScriptBinaryOpcode.COMM;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithCommReferenceOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 0 });
            ExpectedDisassemblyText = "COMM 0";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }
    }
}