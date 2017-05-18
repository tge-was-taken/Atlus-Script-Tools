using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class MessageScriptTests
    {
        [TestMethod()]
        public void FromBinaryTest()
        {
            var script = MessageScript.FromBinary(MessageScriptBinary.FromFile("TestResources\\V1.bmd"));
        }

        [TestMethod()]
        public void MessageScriptTest()
        {
            Assert.Inconclusive();
        }
    }
}