using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib.FlowScript.CommTables;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AtlusScriptLib.Shared.Syntax;

namespace AtlusScriptLib.FlowScript.CommTables.Tests
{
    [TestClass()]
    public class CommTableParserTests
    {
        CommTableParser parser;

        [TestMethod()]
        public void CommTableParserTest()
        {
            parser = new CommTableParser("FlowScript\\CommTables\\p5table.txt");
        }

        [TestMethod()]
        public void TryParseEntryTest()
        {
            parser = new CommTableParser("FlowScript\\CommTables\\p5table.txt");

            Assert.IsTrue(parser.TryParseEntry(out CommTableEntry entry));
            Assert.AreEqual(0, entry.Id);
            Assert.AreEqual("SYNC", entry.Declaration.Identifier.Name);
            Assert.AreEqual(FunctionDeclarationFlags.ReturnTypeVoid, entry.Declaration.Flags);
            Assert.AreEqual(0, entry.Declaration.ArgumentList.Arguments.Count);

            Assert.IsTrue(parser.TryParseEntry(out entry));
            Assert.AreEqual(1, entry.Id);
            Assert.AreEqual("WAIT", entry.Declaration.Identifier.Name);
            Assert.AreEqual(FunctionDeclarationFlags.ReturnTypeVoid, entry.Declaration.Flags);
            Assert.AreEqual(1, entry.Declaration.ArgumentList.Arguments.Count);

            var varDeclaration = entry.Declaration.ArgumentList.Arguments[0] as VariableDeclaration;
            Assert.AreEqual(VariableDeclarationFlags.TypeInt, varDeclaration.Flags);
            Assert.AreEqual("arg0", varDeclaration.Identifier.Name);

            for (int i = 0; i < 7; i++)
            {
                Assert.IsTrue(parser.TryParseEntry(out entry));
            }

            Assert.IsTrue(parser.TryParseEntry(out entry));
            Assert.AreEqual(9, entry.Id);
            Assert.AreEqual("FADEEND_CHECK", entry.Declaration.Identifier.Name);
            Assert.AreEqual(FunctionDeclarationFlags.ReturnTypeVoid, entry.Declaration.Flags);
            Assert.AreEqual(0, entry.Declaration.ArgumentList.Arguments.Count);
        }

        [TestMethod()]
        public void ParseTest()
        {
            var dictionary = CommTableParser.Parse("FlowScript\\CommTables\\p5table.txt");
            Assert.AreEqual(1878, dictionary.Count);
        }
    }
}