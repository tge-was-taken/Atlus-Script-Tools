using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class MessageScriptTests
    {
        [TestMethod()]
        public void FromBinary_ShouldNotThrow_Version1()
        {
            var binary = MessageScriptBinary.FromFile("TestResources\\Version1.bmd");
            var script = MessageScript.FromBinary(binary);
        }

        [TestMethod()]
        public void FromBinary_ShouldNotThrow_Version1BigEndian()
        {
            var binary = MessageScriptBinary.FromFile("TestResources\\Version1BigEndian.bmd");
            var script = MessageScript.FromBinary(binary);
        }

        [TestMethod()]
        public void FromFile_ShouldNotThrow_Version1()
        {
            var script = MessageScript.FromFile("TestResources\\Version1.bmd");
        }

        [TestMethod()]
        public void FromFile_ShouldNotThrow_Version1BigEndian()
        {
            var script = MessageScript.FromFile("TestResources\\Version1BigEndian.bmd");
        }

        [TestMethod()]
        public void FromStream_ShouldNotThrow_Version1()
        {
            using (var fileStream = File.OpenRead("TestResources\\Version1.bmd"))
            {
                var script = MessageScript.FromStream(fileStream);
            }
        }

        [TestMethod()]
        public void FromStream_ShouldNotThrow_Version1BigEndian()
        {
            using (var fileStream = File.OpenRead("TestResources\\Version1BigEndian.bmd"))
            {
                var script = MessageScript.FromStream(fileStream);
            }
        }

        [TestMethod()]
        public void Constructor_ShouldNotFailDefaultValueCheck()
        {
            var script = new MessageScript();

            Assert.AreEqual(0, script.UserId);
            Assert.AreEqual(MessageScriptBinaryFormatVersion.Unknown, script.FormatVersion);
            Assert.AreEqual(0, script.Messages.Count);
        }
    }
}