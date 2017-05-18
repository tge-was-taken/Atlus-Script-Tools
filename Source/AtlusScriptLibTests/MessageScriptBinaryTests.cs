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
        MessageScriptBinary script;

        [TestMethod()]
        public void FromFileTest_V1()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void FromFileTest_V1_RightVersion()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1.bmd", MessageScriptBinaryFormatVersion.V1);
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void FromFileTest_V1_WrongVersion()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1.bmd", MessageScriptBinaryFormatVersion.V1_BE);
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void FromFileTest_V1_BE()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd");
            DoScriptChecks_V1_BE();
        }

        [TestMethod()]
        public void FromFileTest_V1_BE_RightVersion()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd", MessageScriptBinaryFormatVersion.V1_BE);
            DoScriptChecks_V1_BE();
        }

        [TestMethod()]
        public void FromFileTest_V1_BE_WrongVersion()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd", MessageScriptBinaryFormatVersion.V1_BE);
            DoScriptChecks_V1_BE();
        }

        [TestMethod()]
        public void FromStreamTest()
        {
            script = MessageScriptBinary.FromStream(File.OpenRead("TestResources\\V1.bmd"));
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void ToFileTest_V1()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            script.ToFile("TestResources\\V1_ToFileTest.bmd");
            script = MessageScriptBinary.FromFile("TestResources\\V1_ToFileTest.bmd");
            DoScriptChecks_V1();
        }

        [TestMethod()]
        public void ToFileTest_V1_BE()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1_BE.bmd");
            script.ToFile("TestResources\\V1_BE_ToFileTest.bmd");
            script = MessageScriptBinary.FromFile("TestResources\\V1_BE_ToFileTest.bmd");
            DoScriptChecks_V1_BE();
        }

        [TestMethod()]
        public void ToStreamTest()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            var stream = script.ToStream();
            Assert.IsNotNull(stream);
            Assert.AreNotEqual(0, stream.Length);
            Assert.AreEqual(script.Header.FileSize, stream.Length);
        }

        [TestMethod()]
        public void ToStreamTest1()
        {
            script = MessageScriptBinary.FromFile("TestResources\\V1.bmd");
            var stream = new MemoryStream();
            script.ToStream(stream);
            Assert.IsNotNull(stream);
            Assert.AreNotEqual(0, stream.Length);
            Assert.AreEqual(script.Header.FileSize, stream.Length);
        }

        private void DoScriptChecks_V1()
        {
            // header checks
            Assert.AreEqual(7, script.Header.FileType);
            Assert.AreEqual(false, script.Header.IsCompressed);
            Assert.AreEqual(0, script.Header.UserId);
            Assert.AreEqual(0x987A, script.Header.FileSize);
            Assert.IsTrue(script.Header.Magic.SequenceEqual(MessageScriptBinaryHeader.MAGIC_LE));
            Assert.AreEqual(0, script.Header.Field0C);
            Assert.AreEqual(0x96EC, script.Header.RelocationTable.Address);
            Assert.AreEqual(0x018E, script.Header.RelocationTable.Value.Length);
            Assert.AreEqual(0x018E, script.Header.RelocationTableSize);
            Assert.AreEqual(0x9B, script.Header.MessageCount);
            Assert.AreEqual(0x9B, script.MessageHeaders.Count);
            Assert.AreEqual(false, script.Header.IsRelocated);
            Assert.AreEqual(2, script.Header.Field1E);

            // check some message headers
            Assert.AreEqual(MessageScriptBinaryMessageType.Selection, script.MessageHeaders[0].MessageType);
            Assert.AreEqual(0x04E8, script.MessageHeaders[0].Message.Address);

            Assert.AreEqual(MessageScriptBinaryMessageType.Dialogue, script.MessageHeaders[26].MessageType);
            Assert.AreEqual(0x1B68, script.MessageHeaders[26].Message.Address);

            // check some messages
            Assert.AreEqual("combine_sel", ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Identifier);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Field18);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionCount);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Field1C);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Field1E);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionStartAddresses.Length);
            Assert.AreEqual(0x0514, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionStartAddresses[0]);
            Assert.AreEqual(0x051E, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionStartAddresses[1]);
            Assert.AreEqual(0x14, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).TextBufferSize);
            Assert.AreEqual(0x14, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).TextBuffer.Length);

            Assert.AreEqual("book_bonus004", ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).Identifier);
            Assert.AreEqual(0x0A, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).LineCount);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).SpeakerId);
            Assert.AreEqual(0x0A, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).LineStartAddresses.Length);
            Assert.AreEqual(0x1BB0, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).LineStartAddresses[0]);
            Assert.AreEqual(0x1C1C, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).LineStartAddresses[1]);
            Assert.AreEqual(0x02CE, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).TextBufferSize);
            Assert.AreEqual(0x02CE, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).TextBuffer.Length);
        }

        private void DoScriptChecks_V1_BE()
        {
            // header checks
            Assert.AreEqual(7, script.Header.FileType);
            Assert.AreEqual(false, script.Header.IsCompressed);
            Assert.AreEqual(0, script.Header.UserId);
            Assert.AreEqual(0x6F89, script.Header.FileSize);
            Assert.IsTrue(script.Header.Magic.SequenceEqual(MessageScriptBinaryHeader.MAGIC_BE));
            Assert.AreEqual(0, script.Header.Field0C);
            Assert.AreEqual(0x6E50, script.Header.RelocationTable.Address);
            Assert.AreEqual(0x0139, script.Header.RelocationTableSize);
            Assert.AreEqual(script.Header.RelocationTableSize, script.Header.RelocationTable.Value.Length);
            Assert.AreEqual(0x76, script.Header.MessageCount);
            Assert.AreEqual(script.Header.MessageCount, script.MessageHeaders.Count);
            Assert.AreEqual(false, script.Header.IsRelocated);
            Assert.AreEqual(2, script.Header.Field1E);

            // check some message headers
            Assert.AreEqual(MessageScriptBinaryMessageType.Selection, script.MessageHeaders[0].MessageType);
            Assert.AreEqual(0x03C0, script.MessageHeaders[0].Message.Address);

            Assert.AreEqual(MessageScriptBinaryMessageType.Dialogue, script.MessageHeaders[26].MessageType);
            Assert.AreEqual(0x0F24, script.MessageHeaders[26].Message.Address);

            // check some messages
            Assert.AreEqual("FCL_MSG_COMBINE_SELECT", ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Identifier);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Field18);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionCount);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Field1C);
            Assert.AreEqual(0, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).Field1E);
            Assert.AreEqual(2, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionStartAddresses.Length);
            Assert.AreEqual(0x03EC, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionStartAddresses[0]);
            Assert.AreEqual(0x03FC, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).OptionStartAddresses[1]);
            Assert.AreEqual(0x23, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).TextBufferSize);
            Assert.AreEqual(0x23, ((MessageScriptBinarySelectionMessage)script.MessageHeaders[0].Message.Value).TextBuffer.Length);

            Assert.AreEqual("FCL_MSG_COMBINE_CELL_HOU", ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).Identifier);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).LineCount);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).SpeakerId);
            Assert.AreEqual(0x01, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).LineStartAddresses.Length);
            Assert.AreEqual(0x0F48, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).LineStartAddresses[0]);
            Assert.AreEqual(0x40, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).TextBufferSize);
            Assert.AreEqual(0x40, ((MessageScriptBinaryDialogueMessage)script.MessageHeaders[26].Message.Value).TextBuffer.Length);
        }
    }
}