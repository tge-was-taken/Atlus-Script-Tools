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
            var script = MessageScript.FromBinary(MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd"));
        }

        [TestMethod()]
        public void MessageScriptTest()
        {
            Assert.Inconclusive();
        }
    }
}