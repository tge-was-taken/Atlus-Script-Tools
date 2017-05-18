using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace AtlusScriptLib.Common.Tokenizing.Tests
{
    [TestClass()]
    public class TokenizerTests : IDisposable
    {
        private bool mDisposed;
        private Tokenizer mTokenizer;

        [TestMethod()]
        public void TokenizerTest_String()
        {
            mTokenizer = new Tokenizer("test", null);
        }

        [TestMethod()]
        public void TokenizerTest_Stream()
        {
            mTokenizer = new Tokenizer(new MemoryStream(), null);
        }

        [TestMethod()]
        public void DisposeTest()
        {
            mTokenizer = new Tokenizer("", null);
            mTokenizer.Dispose();
        }

        [TestMethod()]
        public void GetTokenTest()
        {
            mTokenizer = new Tokenizer(" Abc,@!\\123!0x123       ", null);

            int index = 0;
            while (mTokenizer.TryGetToken(out Token token))
            {
                switch (index)
                {
                    case 0:
                        Assert.AreEqual("Abc", token.Text);
                        break;

                    case 1:
                        Assert.AreEqual(",", token.Text);
                        break;

                    case 2:
                        Assert.AreEqual("@", token.Text);
                        break;

                    case 3:
                        Assert.AreEqual("!", token.Text);
                        break;

                    case 4:
                        Assert.AreEqual("\\", token.Text);
                        break;

                    case 5:
                        Assert.AreEqual("123", token.Text);
                        break;

                    case 6:
                        Assert.AreEqual("!", token.Text);
                        break;

                    case 7:
                        Assert.AreEqual("0x123", token.Text);
                        break;
                }

                index++;
            }
        }

        [TestMethod()]
        public void GetTokenTest_CommTableDeclaration()
        {
            mTokenizer = new Tokenizer("0005 void MSG(int arg0, unk arg1);", null);

            int index = 0;
            while (mTokenizer.TryGetToken(out Token token))
            {
                switch (index)
                {
                    case 0:
                        Assert.AreEqual("0005", token.Text);
                        break;
                    case 1:
                        Assert.AreEqual("void", token.Text);
                        break;
                    case 2:
                        Assert.AreEqual("MSG", token.Text);
                        break;
                    case 3:
                        Assert.AreEqual("(", token.Text);
                        break;
                    case 4:
                        Assert.AreEqual("int", token.Text);
                        break;
                    case 5:
                        Assert.AreEqual("arg0", token.Text);
                        break;
                    case 6:
                        Assert.AreEqual(",", token.Text);
                        break;
                    case 7:
                        Assert.AreEqual("unk", token.Text);
                        break;
                    case 8:
                        Assert.AreEqual("arg1", token.Text);
                        break;
                    case 9:
                        Assert.AreEqual(")", token.Text);
                        break;
                    case 10:
                        Assert.AreEqual(";", token.Text);
                        break;
                }

                index++;
            }
        }

        [TestMethod()]
        public void GetTokenTest_Whitespace()
        {
            mTokenizer = new Tokenizer(" @  !    abc", null)
            {
                KeepWhitespace = true
            };

            int index = 0;
            while (mTokenizer.TryGetToken(out Token token))
            {
                switch (index)
                {
                    case 0:
                        Assert.AreEqual(" ", token.Text);
                        break;

                    case 1:
                        Assert.AreEqual("@", token.Text);
                        break;

                    case 2:
                        Assert.AreEqual("  ", token.Text);
                        break;

                    case 3:
                        Assert.AreEqual("!", token.Text);
                        break;

                    case 4:
                        Assert.AreEqual("    ", token.Text);
                        break;

                    case 5:
                        Assert.AreEqual("abc", token.Text);
                        break;
                }

                index++;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (mDisposed)
                return;

            mTokenizer.Dispose();
            mDisposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }
    }
}