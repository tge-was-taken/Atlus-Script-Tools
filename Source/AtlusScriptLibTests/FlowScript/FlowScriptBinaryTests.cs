using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace AtlusScriptLib.FlowScript.Tests
{
    [TestClass()]
    public class FlowScriptBinaryTests
    {
        private void LoadFromFileTestBase(string path, FlowScriptBinaryVersion version, FlowScriptBinaryVersion actualVersion)
        {
            var result = FlowScriptBinary.LoadFromFile(path, version, out FlowScriptBinary script);

            Assert.AreEqual(FlowScriptBinaryLoadResult.OK, result, $"{nameof(FlowScriptBinaryLoadResult)} value is not OK");
            Assert.IsNotNull(script, "Script object should not be null");
            Assert.AreEqual(actualVersion, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_KnownVersion()
        {
            LoadFromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryVersion.V1, FlowScriptBinaryVersion.V1);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_UnknownVersion()
        {
            LoadFromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryVersion.Unknown, FlowScriptBinaryVersion.V1);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_WrongVersion()
        {
            LoadFromFileTestBase("TestResources\\V1.bf", FlowScriptBinaryVersion.V3_BE, FlowScriptBinaryVersion.V1);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_KnownVersion()
        {
            LoadFromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryVersion.V2, FlowScriptBinaryVersion.V2);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_UnknownVersion()
        {
            LoadFromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryVersion.Unknown, FlowScriptBinaryVersion.V2);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_WrongVersion()
        {
            LoadFromFileTestBase("TestResources\\V2.bf", FlowScriptBinaryVersion.V3_BE, FlowScriptBinaryVersion.V2);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_KnownVersion()
        {
            LoadFromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryVersion.V3_BE, FlowScriptBinaryVersion.V3_BE);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_UnknownVersion()
        {
            LoadFromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryVersion.Unknown, FlowScriptBinaryVersion.V3_BE);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_WrongVersion()
        {
            LoadFromFileTestBase("TestResources\\V3_BE.bf", FlowScriptBinaryVersion.V1, FlowScriptBinaryVersion.V3_BE);
        }

        [TestMethod()]
        public void LoadFromFileTest_InvalidFileFormat_Small()
        {
            var result = FlowScriptBinary.LoadFromFile("TestResources\\dummy_small.bin", FlowScriptBinaryVersion.Unknown, out FlowScriptBinary script);

            Assert.AreEqual(FlowScriptBinaryLoadResult.InvalidFormat, result);
            Assert.IsNull(script);
        }

        [TestMethod()]
        public void LoadFromFileTest_InvalidFileFormat_Big()
        {
            var result = FlowScriptBinary.LoadFromFile("TestResources\\dummy_big.bin", FlowScriptBinaryVersion.Unknown, out FlowScriptBinary script);

            Assert.AreEqual(FlowScriptBinaryLoadResult.InvalidFormat, result);
            Assert.IsNull(script);
        }

        [TestMethod()]
        [Ignore]
        public void LoadFromFileTest_Batch()
        {
            foreach (var path in Directory.EnumerateFiles("TestResources\\Batch\\", "*.bf"))
            {
                var result = FlowScriptBinary.LoadFromFile(path, FlowScriptBinaryVersion.V3_BE, out FlowScriptBinary script);

                Assert.AreEqual(FlowScriptBinaryLoadResult.OK, result, $"{nameof(FlowScriptBinaryLoadResult)} value is not OK");
                Assert.IsNotNull(script, "Script object should not be null");
            }
        }

        [TestMethod()]
        public void LoadFromStreamTest()
        {
            using (var fileStream = File.OpenRead("TestResources\\V3_BE.bf"))
            {
                var result = FlowScriptBinary.LoadFromStream(fileStream, FlowScriptBinaryVersion.V3_BE, out FlowScriptBinary script);

                Assert.AreEqual(FlowScriptBinaryLoadResult.OK, result);
                Assert.IsNotNull(script);
                Assert.AreEqual(FlowScriptBinaryVersion.V3_BE, script.Version);
            }
        }
    }
}