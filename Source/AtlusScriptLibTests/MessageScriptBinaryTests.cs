using Microsoft.VisualStudio.TestTools.UnitTesting;
using AtlusScriptLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace AtlusScriptLib.Tests
{
    [TestClass()]
    public class MessageScriptBinaryTests
    {
        private MessageScriptBinary mScript;

        [TestMethod()]
        public void FromFileTest_V1()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void FromFileTest_V1_RightVersion()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1.bmd", MessageScriptBinaryFormatVersion.V1);
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void FromFileTest_V1_WrongVersion()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1.bmd", MessageScriptBinaryFormatVersion.V1_BE);
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void FromFileTest_V1_BE()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd");
            DoScriptChecks_V1_BE();
        }

        [TestMethod()]
        public void FromFileTest_V1_BE_RightVersion()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd", MessageScriptBinaryFormatVersion.V1_BE);
            DoScriptChecks_V1_BE();
        }

        [TestMethod()]
        public void FromFileTest_V1_BE_WrongVersion()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd", MessageScriptBinaryFormatVersion.V1_BE);
            DoScriptChecks_V1_BE();
        }

        [TestMethod]
        //[Ignore]
        public void FromFileTest_Batch()
        {
            foreach (var path in Directory.EnumerateFiles("TestResources\\Batch\\", "*.bmd"))
            {
                mScript = MessageScriptBinary.FromFile(path);
            }
        }

        [TestMethod()]
        public void FromStreamTest()
        {
            mScript = MessageScriptBinary.FromStream(File.OpenRead("TestResources\\V1.bmd"));
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void ToFileTest_V1()
        {
            try
            {
                mScript = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
                mScript.ToFile("TestResources\\V1_ToFileTest.bmd");
                mScript = MessageScriptBinary.FromFile("TestResources\\V1_ToFileTest.bmd");
                DoScriptChecks_V1();
            }
            finally
            {
                File.Delete("TestResources\\V1_ToFileTest.bmd");
            }     
        }

        [TestMethod()]
        public void ToFileTest_V1_BE()
        {
            try
            {
                mScript = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd");
                mScript.ToFile("TestResources\\V1_BE_ToFileTest.bmd");
                mScript = MessageScriptBinary.FromFile("TestResources\\V1_BE_ToFileTest.bmd");
                DoScriptChecks_V1_BE();
            }
            finally
            {
                File.Delete("TestResources\\V1_BE_ToFileTest.bmd");
            }       
        }

        [TestMethod()]
        public void ToStreamTest()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            var stream = mScript.ToStream();
            Assert.IsNotNull(stream);
            Assert.AreNotEqual(0, stream.Length);
            Assert.AreEqual(mScript.Header.FileSize, stream.Length);
        }

        [TestMethod()]
        public void ToStreamTest1()
        {
            mScript = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            var stream = new MemoryStream();
            mScript.ToStream(stream);
            Assert.IsNotNull(stream);
            Assert.AreNotEqual(0, stream.Length);
            Assert.AreEqual(mScript.Header.FileSize, stream.Length);
        }

        private void DoScriptChecks_V1()
        {
            // header checks
            Assert.AreEqual(7, mScript.Header.FileType);
            Assert.AreEqual(false, mScript.Header.IsCompressed);
            Assert.AreEqual(0, mScript.Header.UserId);
            Assert.AreEqual(0x987A, mScript.Header.FileSize);
            Assert.IsTrue(mScript.Header.Magic.SequenceEqual(MessageScriptBinaryHeader.MAGIC_V1));
            Assert.AreEqual(0, mScript.Header.Field0C);
            Assert.AreEqual(0x96EC, mScript.Header.RelocationTable.Address);
            Assert.AreEqual(0x018E, mScript.Header.RelocationTable.Value.Length);
            Assert.AreEqual(0x018E, mScript.Header.RelocationTableSize);
            Assert.AreEqual(0x9B, mScript.Header.MessageCount);
            Assert.AreEqual(0x9B, mScript.MessageHeaders.Count);
            Assert.AreEqual(false, mScript.Header.IsRelocated);
            Assert.AreEqual(2, mScript.Header.Field1E);

            // check some message headers
            Assert.AreEqual(MessageScriptBinaryMessageType.Selection, mScript.MessageHeaders[0].MessageType);
            Assert.AreEqual(0x04E8, mScript.MessageHeaders[0].Message.Address);

            Assert.AreEqual(MessageScriptBinaryMessageType.Dialogue, mScript.MessageHeaders[26].MessageType);
            Assert.AreEqual(0x1B68, mScript.MessageHeaders[26].Message.Address);

            // check some messages
            Assert.AreEqual("combine_sel", ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Identifier);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Field18);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionCount);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Field1C);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Field1E);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionStartAddresses.Length);
            Assert.AreEqual(0x0514, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionStartAddresses[0]);
            Assert.AreEqual(0x051E, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionStartAddresses[1]);
            Assert.AreEqual(0x14, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).TextBufferSize);
            Assert.AreEqual(0x14, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).TextBuffer.Length);

            Assert.AreEqual("book_bonus004", ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).Identifier);
            Assert.AreEqual(0x0A, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).LineCount);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).SpeakerId);
            Assert.AreEqual(0x0A, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).LineStartAddresses.Length);
            Assert.AreEqual(0x1BB0, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).LineStartAddresses[0]);
            Assert.AreEqual(0x1C1C, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).LineStartAddresses[1]);
            Assert.AreEqual(0x02CE, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).TextBufferSize);
            Assert.AreEqual(0x02CE, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).TextBuffer.Length);
        }

        private void DoScriptChecks_V1_BE()
        {
            // header checks
            Assert.AreEqual(7, mScript.Header.FileType);
            Assert.AreEqual(false, mScript.Header.IsCompressed);
            Assert.AreEqual(0, mScript.Header.UserId);
            Assert.AreEqual(0x6F89, mScript.Header.FileSize);
            Assert.IsTrue(mScript.Header.Magic.SequenceEqual(MessageScriptBinaryHeader.MAGIC_V1_BE));
            Assert.AreEqual(0, mScript.Header.Field0C);
            Assert.AreEqual(0x6E50, mScript.Header.RelocationTable.Address);
            Assert.AreEqual(0x0139, mScript.Header.RelocationTableSize);
            Assert.AreEqual(mScript.Header.RelocationTableSize, mScript.Header.RelocationTable.Value.Length);
            Assert.AreEqual(0x76, mScript.Header.MessageCount);
            Assert.AreEqual(mScript.Header.MessageCount, mScript.MessageHeaders.Count);
            Assert.AreEqual(false, mScript.Header.IsRelocated);
            Assert.AreEqual(2, mScript.Header.Field1E);

            // check some message headers
            Assert.AreEqual(MessageScriptBinaryMessageType.Selection, mScript.MessageHeaders[0].MessageType);
            Assert.AreEqual(0x03C0, mScript.MessageHeaders[0].Message.Address);

            Assert.AreEqual(MessageScriptBinaryMessageType.Dialogue, mScript.MessageHeaders[26].MessageType);
            Assert.AreEqual(0x0F24, mScript.MessageHeaders[26].Message.Address);

            // check some messages
            Assert.AreEqual("FCL_MSG_COMBINE_SELECT", ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Identifier);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Field18);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionCount);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Field1C);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).Field1E);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionStartAddresses.Length);
            Assert.AreEqual(0x03EC, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionStartAddresses[0]);
            Assert.AreEqual(0x03FC, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).OptionStartAddresses[1]);
            Assert.AreEqual(0x23, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).TextBufferSize);
            Assert.AreEqual(0x23, ((MessageScriptBinarySelectionMessage)mScript.MessageHeaders[0].Message.Value).TextBuffer.Length);

            Assert.AreEqual("FCL_MSG_COMBINE_CELL_HOU", ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).Identifier);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).LineCount);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).SpeakerId);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).LineStartAddresses.Length);
            Assert.AreEqual(0x0F48, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).LineStartAddresses[0]);
            Assert.AreEqual(0x40, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).TextBufferSize);
            Assert.AreEqual(0x40, ((MessageScriptBinaryDialogueMessage)mScript.MessageHeaders[26].Message.Value).TextBuffer.Length);
        }
    }
}