using System.Collections.Generic;
using System.IO;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib.Disassemblers;
using System;

namespace AtlusScriptLib.Disassembler.Tests
{
    [TestClass()]
    public class FlowScriptBinaryDisassemblerTests : IDisposable
    {
        private bool mDisposed;
        public FlowScriptBinaryDisassembler Disassembler;
        public FlowScriptBinary Script;
        public string DisassemblyText;
        public string ExpectedDisassemblyText;
        public FlowScriptOpcode Opcode;

        private void DisassembleToFileTestBase(string path)
        {
            Script = FlowScriptBinary.FromFile(path, FlowScriptBinaryFormatVersion.Unknown);
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
            var script = FlowScriptBinary.FromFile("TestResources\\V1.bf");
            var builder = new StringBuilder();
            Disassembler = new FlowScriptBinaryDisassembler(builder);
            Disassembler.Disassemble(script);
        }

        [TestMethod()]
        public void DisassembleInstructionWithIntOperandTest()
        {
            Opcode = FlowScriptOpcode.PUSHI;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithIntOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode }, new FlowScriptBinaryInstruction() { OperandInt = 42 });
            ExpectedDisassemblyText = "PUSHI 42";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithFloatOperandTest()
        {
            Opcode = FlowScriptOpcode.PUSHF;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithFloatOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode }, new FlowScriptBinaryInstruction() { OperandFloat = 42.42f });
            ExpectedDisassemblyText = "PUSHF 42.42f";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithShortOperandTest()
        {
            Opcode = FlowScriptOpcode.PUSHIS;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithShortOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 42 });
            ExpectedDisassemblyText = "PUSHIS 42";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithStringReferenceOperandTest()
        {
            Opcode = FlowScriptOpcode.PUSHSTR;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithStringReferenceOperand(
                new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 0 },
                Encoding.ASCII.GetBytes("foobar")
                );

            ExpectedDisassemblyText = "PUSHSTR \"foobar\"";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithLabelReferenceOperandTest()
        {
            string labelName = "foobar";
            Opcode = FlowScriptOpcode.PROC;
            ExpectedDisassemblyText = $"PROC {labelName}";
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithLabelReferenceOperand(
                new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 0 },
                new List<FlowScriptBinaryLabel>() { new FlowScriptBinaryLabel() {  InstructionIndex = 0, Name = labelName, Reserved = 0 } }
                );          

            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithNoOperandTest()
        {
            Opcode = FlowScriptOpcode.ADD;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithNoOperand(new FlowScriptBinaryInstruction() { Opcode = FlowScriptOpcode.ADD });
            ExpectedDisassemblyText = "ADD";

            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        [TestMethod()]
        public void DisassembleInstructionWithCommReferenceTest()
        {
            Opcode = FlowScriptOpcode.COMM;
            DisassemblyText = FlowScriptBinaryDisassembler.DisassembleInstructionWithCommReferenceOperand(new FlowScriptBinaryInstruction() { Opcode = Opcode, OperandShort = 0 });
            ExpectedDisassemblyText = "COMM 0";
            Assert.AreEqual(ExpectedDisassemblyText, DisassemblyText, $"Opcode {Opcode} should dissassemble to \"{ExpectedDisassemblyText}\", got {DisassemblyText}");
        }

        protected virtual void Dispose(bool disposing)
        {
            if (mDisposed)
                return;

            if (Disassembler != null)
                Disassembler.Dispose();
            mDisposed = true;
        }

        public void Dispose()
        { 
            Dispose(true);
        }
    }
}