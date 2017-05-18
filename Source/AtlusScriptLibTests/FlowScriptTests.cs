using AtlusScriptLib;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class FlowScriptTests
    {
        FlowScript Script;

        private void FromFileTestBase(string path, FlowScriptBinaryFormatVersion version, FlowScriptBinaryFormatVersion actualVersion)
        {
            Script = FlowScript.FromFile(path, version);

            Assert.IsNotNull(Script, "Script object should not be null");
            Assert.AreEqual(actualVersion, Script.FormatVersion);
        }

        [TestMethod()]
        public void FromFileTest_V1_KnownVersion()
        {
            FromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryFormatVersion.V1, FlowScriptBinaryFormatVersion.V1);

            Assert.AreEqual(10061, Script.Instructions.Count);
            Assert.AreEqual(742, Script.JumpLabels.Count);
            Assert.AreEqual(77521, Script.MessageScript.Length);
            Assert.AreEqual(96, Script.ProcedureLabels.Count);
            Assert.AreEqual(240, Script.Strings.Count);
            Assert.AreEqual(FlowScriptOpcode.COMM, Script.Instructions[2].Opcode);
            Assert.AreEqual(102, Script.Instructions[2].Operand.GetInt16Value());
            Assert.ThrowsException<InvalidOperationException>(() => Script.Instructions[2].Operand.GetInt32Value());
        }

        [TestMethod()]
        public void FromFileTest_V1_UnknownVersion()
        {
            FromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.V1);
        }

        [TestMethod()]
        public void FromFileTest_V1_WrongVersion()
        {
            FromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryFormatVersion.V3_BE, FlowScriptBinaryFormatVersion.V1);
        }

        [TestMethod()]
        public void FromFileTest_V2_KnownVersion()
        {
            FromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryFormatVersion.V2, FlowScriptBinaryFormatVersion.V2);
        }

        [TestMethod()]
        public void FromFileTest_V2_UnknownVersion()
        {
            FromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.V2);
        }

        [TestMethod()]
        public void FromFileTest_V2_WrongVersion()
        {
            FromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryFormatVersion.V3_BE, FlowScriptBinaryFormatVersion.V2);
        }

        [TestMethod()]
        public void FromFileTest_V3_BE_KnownVersion()
        {
            FromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryFormatVersion.V3_BE, FlowScriptBinaryFormatVersion.V3_BE);
        }

        [TestMethod()]
        public void FromFileTest_V3_BE_UnknownVersion()
        {
            FromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.V3_BE);
        }

        [TestMethod()]
        public void FromFileTest_V3_BE_WrongVersion()
        {
            FromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryFormatVersion.V1, FlowScriptBinaryFormatVersion.V3_BE);
        }

        [TestMethod()]
        public void FromFileTest_InvalidFileFormat_Small()
        {
            Assert.ThrowsException<InvalidDataException>(() => FlowScript.FromFile("TestResources\\dummy_small.bin", FlowScriptBinaryFormatVersion.Unknown));
        }

        [TestMethod()]
        public void FromFileTest_InvalidFileFormat_Big()
        {
            Assert.ThrowsException<InvalidDataException>(() => FlowScript.FromFile("TestResources\\dummy_big.bin", FlowScriptBinaryFormatVersion.Unknown));
        }

        [TestMethod()]
        [Ignore]
        public void FromFileTest_Batch()
        {
            foreach (var path in Directory.EnumerateFiles("TestResources\\Batch\\", "*.bf"))
            {
                var script = FlowScript.FromFile(path, FlowScriptBinaryFormatVersion.V3_BE);

                Assert.IsNotNull(script);
            }
        }

        [TestMethod()]
        public void FromStreamTest()
        {
            using (var fileStream = File.OpenRead("TestResources\\V3_BE.bf"))
            {
                var script = FlowScript.FromStream(fileStream, FlowScriptBinaryFormatVersion.V3_BE);

                Assert.IsNotNull(script);
                Assert.AreEqual(FlowScriptBinaryFormatVersion.V3_BE, script.FormatVersion);
            }
        }

        [TestMethod()]
        public void FromBinaryTest()
        {
            var binary = FlowScriptBinary.FromFile("TestResources\\V3_BE.bf", FlowScriptBinaryFormatVersion.V3_BE);
            var script = FlowScript.FromBinary(binary);

            Assert.AreEqual(script.UserId, binary.Header.UserId);

            // Compare label names
            for (int i = 0; i < script.ProcedureLabels.Count; i++)
            {
                Assert.AreEqual(binary.ProcedureLabelSection[i].Name, script.ProcedureLabels[i].Name);
            }

            for (int i = 0; i < script.JumpLabels.Count; i++)
            {
                Assert.AreEqual(binary.JumpLabelSection[i].Name, script.JumpLabels[i].Name);
            }

            // Compare instructions
            for (int i = 0; i < script.Instructions.Count; i++)
            {
                //Assert.AreEqual(binary.TextSection[i].Opcode, script.Instructions[i].Opcode);
            }
        }

        [TestMethod()]
        public void ToBinaryTest()
        {
            var binaryIn = FlowScriptBinary.FromFile("TestResources\\V3_BE.bf");
            var script = FlowScript.FromBinary(binaryIn);
            var binaryOut = script.ToBinary();

            // Compare headers
            Assert.AreEqual(binaryIn.Header.FileType, binaryOut.Header.FileType);
            Assert.AreEqual(binaryIn.Header.Compressed, binaryOut.Header.Compressed);
            Assert.AreEqual(binaryIn.Header.UserId, binaryOut.Header.UserId);
            Assert.AreEqual(binaryIn.Header.FileSize, binaryOut.Header.FileSize);
            Assert.IsTrue(binaryIn.Header.Magic.SequenceEqual(binaryOut.Header.Magic));
            Assert.AreEqual(binaryIn.Header.Field0C, binaryOut.Header.Field0C);
            Assert.AreEqual(binaryIn.Header.SectionCount, binaryOut.Header.SectionCount);
            Assert.AreEqual(binaryIn.Header.LocalIntVariableCount, binaryOut.Header.LocalIntVariableCount);
            Assert.AreEqual(binaryIn.Header.LocalFloatVariableCount, binaryOut.Header.LocalFloatVariableCount);
            Assert.AreEqual(binaryIn.Header.Endianness, binaryOut.Header.Endianness);
            Assert.AreEqual(binaryIn.Header.Field1A, binaryOut.Header.Field1A);
            Assert.AreEqual(binaryIn.Header.Padding, binaryOut.Header.Padding);

            // Compare section headers
            for (int i = 0; i < binaryIn.SectionHeaders.Count; i++)
            {
                Assert.AreEqual(binaryIn.SectionHeaders[i].SectionType, binaryOut.SectionHeaders[i].SectionType);
                Assert.AreEqual(binaryIn.SectionHeaders[i].ElementSize, binaryOut.SectionHeaders[i].ElementSize);
                Assert.AreEqual(binaryIn.SectionHeaders[i].ElementCount, binaryOut.SectionHeaders[i].ElementCount);
                Assert.AreEqual(binaryIn.SectionHeaders[i].FirstElementAddress, binaryOut.SectionHeaders[i].FirstElementAddress);
            }

            // Compare labels
            for (int i = 0; i < binaryIn.ProcedureLabelSection.Count; i++)
            {
                Assert.AreEqual(binaryIn.ProcedureLabelSection[i].Name, binaryOut.ProcedureLabelSection[i].Name);
                Assert.AreEqual(binaryIn.ProcedureLabelSection[i].InstructionIndex, binaryOut.ProcedureLabelSection[i].InstructionIndex);
                Assert.AreEqual(binaryIn.ProcedureLabelSection[i].Reserved, binaryOut.ProcedureLabelSection[i].Reserved);
            }

            for (int i = 0; i < binaryIn.JumpLabelSection.Count; i++)
            {
                Assert.AreEqual(binaryIn.JumpLabelSection[i].Name, binaryOut.JumpLabelSection[i].Name);
                Assert.AreEqual(binaryIn.JumpLabelSection[i].InstructionIndex, binaryOut.JumpLabelSection[i].InstructionIndex);
                Assert.AreEqual(binaryIn.JumpLabelSection[i].Reserved, binaryOut.JumpLabelSection[i].Reserved);
            }

            // Compare instructions
            for (int i = 0; i < binaryIn.TextSection.Count; i++)
            {
                Assert.AreEqual(binaryIn.TextSection[i].Opcode, binaryIn.TextSection[i].Opcode);
            }

            // Compare message script
            Assert.IsTrue(binaryIn.MessageScriptSection.SequenceEqual(binaryOut.MessageScriptSection));

            // Compare strings
            Assert.IsTrue(binaryIn.StringSection.SequenceEqual(binaryOut.StringSection));
        }
    }
}