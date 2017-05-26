using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Decompilers;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class MessageScriptTests
    {
        [TestMethod()]
        public void FromBinaryTest()
        {
            var script = MessageScript.FromBinary(MessageScriptBinary.FromFile("TestResources\\V1.bmd"));

            var decompiler = new MessageScriptDecompiler(script);
            decompiler.Decompile("TestResources\\V1.md");
        }

        [TestMethod()]
        public void MessageScriptTest()
        {
            Assert.Inconclusive();
        }
    }
}