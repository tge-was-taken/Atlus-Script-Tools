using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class FlowScriptBinaryTests
    {
        private void FromFileTestBase(string path, FlowScriptBinaryFormatVersion version, FlowScriptBinaryFormatVersion actualVersion)
        {
            var script = FlowScriptBinary.FromFile(path, version);

            Assert.IsNotNull(script, "Script object should not be null");
            Assert.AreEqual(actualVersion, script.FormatVersion);
        }

        [TestMethod()]
        public void FromFileTest_V1_KnownVersion()
        {
            FromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryFormatVersion.V1, FlowScriptBinaryFormatVersion.V1);
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
            Assert.ThrowsException<InvalidDataException>(() => FlowScriptBinary.FromFile("TestResources\\dummy_small.bin", FlowScriptBinaryFormatVersion.Unknown));
        }

        [TestMethod()]
        public void FromFileTest_InvalidFileFormat_Big()
        {
            Assert.ThrowsException<InvalidDataException>(() => FlowScriptBinary.FromFile("TestResources\\dummy_big.bin", FlowScriptBinaryFormatVersion.Unknown));
        }

        [TestMethod()]
        [Ignore]
        public void FromFileTest_Batch()
        {
            foreach (var path in Directory.EnumerateFiles("TestResources\\Batch\\", "*.bf"))
            {
                var script = FlowScriptBinary.FromFile(path, FlowScriptBinaryFormatVersion.V3_BE);

                Assert.IsNotNull(script);
            }
        }

        [TestMethod()]
        public void FromStreamTest()
        {
            using (var fileStream = File.OpenRead("TestResources\\V3_BE.bf"))
            {
                var script = FlowScriptBinary.FromStream(fileStream, FlowScriptBinaryFormatVersion.V3_BE);

                Assert.IsNotNull(script);
                Assert.AreEqual(FlowScriptBinaryFormatVersion.V3_BE, script.FormatVersion);
            }
        }
    }
}