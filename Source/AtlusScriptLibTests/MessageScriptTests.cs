using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class MessageScriptTests
    {
        [TestMethod()]
        public void FromBinaryTest_V1()
        {
            var binary = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            var script = MessageScript.FromBinary(binary);
        }

        [TestMethod()]
        public void FromBinaryTest_V1_BE()
        {
            var binary = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd");
            var script = MessageScript.FromBinary(binary);
        }

        [TestMethod()]
        public void FromFileTest_V1()
        {
            var script = MessageScript.FromFile("TestResources\\V1.bmd");
        }

        [TestMethod()]
        public void FromFileTest_V1_BE()
        {
            var script = MessageScript.FromFile("TestResources\\V1_BE.bmd");
        }

        [TestMethod()]
        public void FromStreamTest_V1()
        {
            using (var fileStream = File.OpenRead("TestResources\\V1.bmd"))
            {
                var script = MessageScript.FromStream(fileStream);
            }
        }

        [TestMethod()]
        public void FromStreamTest_V1_BE()
        {
            using (var fileStream = File.OpenRead("TestResources\\V1_BE.bmd"))
            {
                var script = MessageScript.FromStream(fileStream);
            }
        }

        [TestMethod()]
        public void MessageScriptTest1()
        {
            var script = new MessageScript();

            Assert.AreEqual(0, script.UserId);
            Assert.AreEqual(MessageScriptBinaryFormatVersion.Unknown, script.FormatVersion);
            Assert.AreEqual(0, script.Messages.Count);
        }
    }
}