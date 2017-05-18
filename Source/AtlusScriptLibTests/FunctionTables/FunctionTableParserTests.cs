using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib.Common.Syntax;
using System;

namespace AtlusScriptLib.FunctionTables.Tests
{
    [TestClass()]
    public class FunctionTableParserTests : IDisposable
    {
        private bool mDisposed;
        private FunctionTableParser mParser;

        [TestMethod()]
        public void FunctionTableParserTest()
        {
            mParser = new FunctionTableParser("FunctionTables\\p5table.txt");
        }

        [TestMethod()]
        public void TryParseEntryTest()
        {
            mParser = new FunctionTableParser("FunctionTables\\p5table.txt");

            Assert.IsTrue(mParser.TryParseEntry(out FunctionTableEntry entry));
            Assert.AreEqual(0, entry.Id);
            Assert.AreEqual("SYNC", entry.Declaration.Identifier.Name);
            Assert.AreEqual(FunctionDeclarationFlags.ReturnTypeVoid, entry.Declaration.Flags);
            Assert.AreEqual(0, entry.Declaration.ArgumentList.Arguments.Count);

            Assert.IsTrue(mParser.TryParseEntry(out entry));
            Assert.AreEqual(1, entry.Id);
            Assert.AreEqual("WAIT", entry.Declaration.Identifier.Name);
            Assert.AreEqual(FunctionDeclarationFlags.ReturnTypeVoid, entry.Declaration.Flags);
            Assert.AreEqual(1, entry.Declaration.ArgumentList.Arguments.Count);

            var varDeclaration = entry.Declaration.ArgumentList.Arguments[0] as VariableDeclaration;
            Assert.AreEqual(VariableDeclarationFlags.TypeInt, varDeclaration.Flags);
            Assert.AreEqual("arg0", varDeclaration.Identifier.Name);

            for (int i = 0; i < 7; i++)
            {
                Assert.IsTrue(mParser.TryParseEntry(out entry));
            }

            Assert.IsTrue(mParser.TryParseEntry(out entry));
            Assert.AreEqual(9, entry.Id);
            Assert.AreEqual("FADEEND_CHECK", entry.Declaration.Identifier.Name);
            Assert.AreEqual(FunctionDeclarationFlags.ReturnTypeVoid, entry.Declaration.Flags);
            Assert.AreEqual(0, entry.Declaration.ArgumentList.Arguments.Count);
        }

        [TestMethod()]
        public void ParseTest()
        {
            var dictionary = FunctionTableParser.Parse("FunctionTables\\p5table.txt");
            Assert.AreEqual(1878, dictionary.Count);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (mDisposed)
                return;
            mParser.Dispose();
            mDisposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }
    }
}