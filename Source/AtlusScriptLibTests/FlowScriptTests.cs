using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class FlowScriptTests
    {
        private void LoadFromFileTestBase(string path, FlowScriptBinaryFormatVersion version, FlowScriptBinaryFormatVersion actualVersion)
        {
            var script = FlowScript.FromFile(path, version);

            Assert.IsNotNull(script, "Script object should not be null");
            Assert.AreEqual(actualVersion, script.FormatVersion);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_KnownVersion()
        {
            LoadFromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryFormatVersion.V1, FlowScriptBinaryFormatVersion.V1);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_UnknownVersion()
        {
            LoadFromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.V1);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_WrongVersion()
        {
            LoadFromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryFormatVersion.V3_BE, FlowScriptBinaryFormatVersion.V1);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_KnownVersion()
        {
            LoadFromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryFormatVersion.V2, FlowScriptBinaryFormatVersion.V2);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_UnknownVersion()
        {
            LoadFromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.V2);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_WrongVersion()
        {
            LoadFromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryFormatVersion.V3_BE, FlowScriptBinaryFormatVersion.V2);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_KnownVersion()
        {
            LoadFromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryFormatVersion.V3_BE, FlowScriptBinaryFormatVersion.V3_BE);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_UnknownVersion()
        {
            LoadFromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryFormatVersion.Unknown, FlowScriptBinaryFormatVersion.V3_BE);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_WrongVersion()
        {
            LoadFromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryFormatVersion.V1, FlowScriptBinaryFormatVersion.V3_BE);
        }

        [TestMethod()]
        public void LoadFromFileTest_InvalidFileFormat_Small()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScript.FromFile("TestResources\\dummy_small.bin", FlowScriptBinaryFormatVersion.Unknown) );
        }

        [TestMethod()]
        public void LoadFromFileTest_InvalidFileFormat_Big()
        {
            Assert.ThrowsException<InvalidDataException>( () => FlowScript.FromFile("TestResources\\dummy_big.bin", FlowScriptBinaryFormatVersion.Unknown) );
        }

        [TestMethod()]
        [Ignore]
        public void LoadFromFileTest_Batch()
        {
            foreach (var path in Directory.EnumerateFiles("TestResources\\Batch\\", "*.bf"))
            {
                var script = FlowScript.FromFile(path, FlowScriptBinaryFormatVersion.V3_BE);

                Assert.IsNotNull(script);
            }
        }

        [TestMethod()]
        public void LoadFromStreamTest()
        {
            using (var fileStream = File.OpenRead("TestResources\\V3_BE.bf"))
            {
                var script = FlowScript.FromStream(fileStream, FlowScriptBinaryFormatVersion.V3_BE);

                Assert.IsNotNull(script);
                Assert.AreEqual(FlowScriptBinaryFormatVersion.V3_BE, script.FormatVersion);
            }
        }
    }
}