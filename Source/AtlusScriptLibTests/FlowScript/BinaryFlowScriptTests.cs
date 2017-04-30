using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace AtlusScriptLib.FlowScript.Tests
{
    [TestClass()]
    public class BinaryFlowScriptTests
    {
        [TestMethod()]
        public void LoadFromFileTest_V1_KnownVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V1.bf", BinaryFlowScriptVersion.V1, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V1, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_UnknownVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V1.bf", BinaryFlowScriptVersion.Unknown, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V1, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V1_WrongVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V1.bf", BinaryFlowScriptVersion.V3_BE, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V1, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_KnownVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V2.bf", BinaryFlowScriptVersion.V2, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V2, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_UnknownVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V2.bf", BinaryFlowScriptVersion.Unknown, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V2, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V2_WrongVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V2.bf", BinaryFlowScriptVersion.V3_BE, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V2, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_KnownVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V3_BE.bf", BinaryFlowScriptVersion.V3_BE, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V3_BE, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_UnknownVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V3_BE.bf", BinaryFlowScriptVersion.Unknown, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V3_BE, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_V3_BE_WrongVersion()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\V3_BE.bf", BinaryFlowScriptVersion.V1, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
            Assert.IsNotNull(script);
            Assert.AreEqual(BinaryFlowScriptVersion.V3_BE, script.Version);
        }

        [TestMethod()]
        public void LoadFromFileTest_InvalidFileFormat_Small()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\dummy_small.bin", BinaryFlowScriptVersion.Unknown, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.InvalidFormat, result);
            Assert.IsNull(script);
        }

        [TestMethod()]
        public void LoadFromFileTest_InvalidFileFormat_Big()
        {
            BinaryFlowScript script;
            var result = BinaryFlowScript.LoadFromFile("TestResources\\dummy_big.bin", BinaryFlowScriptVersion.Unknown, out script);

            Assert.AreEqual(BinaryFlowScriptLoadResult.InvalidFormat, result);
            Assert.IsNull(script);
        }

        [TestMethod()]
        public void LoadFromFileTest_Batch()
        {
            foreach (var path in Directory.EnumerateFiles("TestResources\\Batch\\", "*.bf"))
            {
                BinaryFlowScript script;
                var result = BinaryFlowScript.LoadFromFile(path, BinaryFlowScriptVersion.V3_BE, out script);

                Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result, $"{nameof(BinaryFlowScriptLoadResult)} value is not OK");
                Assert.IsNotNull(script, "Script object should not be null");
            }
        }

        [TestMethod()]
        public void LoadFromStreamTest()
        {
            using (var fileStream = File.OpenRead("TestResources\\V3_BE.bf"))
            {
                BinaryFlowScript script;
                var result = BinaryFlowScript.LoadFromStream(fileStream, BinaryFlowScriptVersion.V3_BE, out script);

                Assert.AreEqual(BinaryFlowScriptLoadResult.OK, result);
                Assert.IsNotNull(script);
                Assert.AreEqual(BinaryFlowScriptVersion.V3_BE, script.Version);
            }
        }
    }
}