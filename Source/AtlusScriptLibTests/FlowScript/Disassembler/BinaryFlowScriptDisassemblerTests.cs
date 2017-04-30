using System.Collections.Generic;
using System.IO;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLib.FlowScript.Disassembler.Tests
{
    [TestClass()]
    public class BinaryFlowScriptDisassemblerTests
    {
        public BinaryFlowScriptDisassembler Disassembler;
        public BinaryFlowScript Script;
        public string DisassemblyText;
        public string ExpectedDisassemblyText;
        public BinaryFlowScriptOpcode Opcode;

        private void DisassembleToFileTestBase(string path)
        {
            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, BinaryFlowScript.LoadFromFile(path, BinaryFlowScriptVersion.Unknown, out Script));
            Disassembler = new BinaryFlowScriptDisassembler(Path.ChangeExtension(path, "flwasm"));
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
            Assert.Fail();
        }

        [TestMethod()]
        public void DisassembleInstructionWithIntOperandTest()
        {
            Opcode = BinaryFlowScriptOpcode.PUSHI;
            DisassemblyText = BinaryFlowScriptDisassembler.DisassembleInstructionWithIntOperand(new BinaryFlowScriptInstruction() { Opcode = Opcode }, new BinaryFlowScriptInstruction() { OperandInt = 42 });
            ExpectedDisassemblyText = "PUSHI 42";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithFloatOperandTest()
        {
            Opcode = BinaryFlowScriptOpcode.PUSHF;
            DisassemblyText = BinaryFlowScriptDisassembler.DisassembleInstructionWithFloatOperand(new BinaryFlowScriptInstruction() { Opcode = Opcode }, new BinaryFlowScriptInstruction() { OperandFloat = 42.42f });
            ExpectedDisassemblyText = "PUSHF 42.42f";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithShortOperandTest()
        {
            Opcode = BinaryFlowScriptOpcode.PUSHIS;
            DisassemblyText = BinaryFlowScriptDisassembler.DisassembleInstructionWithShortOperand(new BinaryFlowScriptInstruction() { Opcode = Opcode, OperandShort = 42 });
            ExpectedDisassemblyText = "PUSHIS 42";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithStringReferenceOperandTest()
        {
            Opcode = BinaryFlowScriptOpcode.PUSHSTR;
            DisassemblyText = BinaryFlowScriptDisassembler.DisassembleInstructionWithStringReferenceOperand(
                new BinaryFlowScriptInstruction() { Opcode = Opcode, OperandShort = 0 },
                new Dictionary<int, string>() { { 0, "foobar" } }
                );

            ExpectedDisassemblyText = "PUSHSTR \"foobar\"";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithLabelReferenceOperandTest()
        {
            string labelName = "foobar";
            Opcode = BinaryFlowScriptOpcode.PROC;
            ExpectedDisassemblyText = $"PROC {labelName}";
            DisassemblyText = BinaryFlowScriptDisassembler.DisassembleInstructionWithLabelReferenceOperand(
                new BinaryFlowScriptInstruction() { Opcode = Opcode, OperandShort = 0 },
                new List<BinaryFlowScriptLabel>() { new BinaryFlowScriptLabel() {  Name = labelName, Offset = 0, Reserved = 0} }
                );          

            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithNoOperandTest()
        {
            Opcode = BinaryFlowScriptOpcode.ADD;
            DisassemblyText = BinaryFlowScriptDisassembler.DisassembleInstructionWithNoOperand(new BinaryFlowScriptInstruction() { Opcode = BinaryFlowScriptOpcode.ADD });
            ExpectedDisassemblyText = "ADD";

            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithCommReferenceTest()
        {
            Opcode = BinaryFlowScriptOpcode.COMM;
            DisassemblyText = BinaryFlowScriptDisassembler.DisassembleInstructionWithCommReferenceOperand(new BinaryFlowScriptInstruction() { Opcode = Opcode, OperandShort = 0 });
            ExpectedDisassemblyText = "COMM 0";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }
    }
}