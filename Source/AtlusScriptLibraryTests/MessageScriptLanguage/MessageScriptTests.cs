using System;
using System.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLibrary.MessageScriptLanguage.Tests
{
    [TestClass]
    public class MessageScriptTests
    {
        [TestMethod]
        public void FromBinary_ShouldNotThrow_Version1()
        {
            var binary = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
            var script = MessageScript.FromBinary( binary );
        }

        [TestMethod]
        public void FromBinary_ShouldNotThrow_Version1BigEndian()
        {
            var binary = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd" );
            var script = MessageScript.FromBinary( binary );
        }

        [TestMethod]
        public void FromFile_ShouldNotThrow_Version1()
        {
            var script = MessageScript.FromFile( "TestResources\\Version1.bmd" );
        }

        [TestMethod]
        public void FromFile_ShouldNotThrow_Version1BigEndian()
        {
            var script = MessageScript.FromFile( "TestResources\\Version1BigEndian.bmd" );
        }

        [TestMethod]
        public void FromStream_ShouldNotThrow_Version1()
        {
            using ( var fileStream = File.OpenRead( "TestResources\\Version1.bmd" ) )
            {
                var script = MessageScript.FromStream( fileStream );
            }
        }

        [TestMethod]
        public void FromStream_ShouldNotThrow_Version1BigEndian()
        {
            using ( var fileStream = File.OpenRead( "TestResources\\Version1BigEndian.bmd" ) )
            {
                var script = MessageScript.FromStream( fileStream );
            }
        }

        [TestMethod]
        public void Constructor_ShouldNotFailDefaultValueCheck()
        {
            var script = new MessageScript( FormatVersion.Version1 );

            Assert.AreEqual( 0, script.Id );
            Assert.AreEqual( FormatVersion.Version1, script.FormatVersion );
            Assert.AreEqual( 0, script.Dialogs.Count );
        }

        [TestMethod]
        public void ToBinary_ShouldMatchSourceBinary_Version1()
        {
            var binary = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
            var script = MessageScript.FromBinary( binary );
            var newBinary = script.ToBinary();

            Compare( binary, newBinary );
        }

        [TestMethod]
        public void ToBinary_ShouldMatchSourceBinary_Version1BigEndian()
        {
            var binary = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd" );
            var script = MessageScript.FromBinary( binary );
            var newBinary = script.ToBinary();

            Compare( binary, newBinary );
        }

        private void Compare( MessageScriptBinary binary, MessageScriptBinary newBinary )
        {
            // compare headers
            Assert.AreEqual( binary.Header.FileType, newBinary.Header.FileType );
            Assert.AreEqual( binary.Header.Format, newBinary.Header.Format );
            Assert.AreEqual( binary.Header.UserId, newBinary.Header.UserId );
            Assert.AreEqual( binary.Header.FileSize, newBinary.Header.FileSize );
            CollectionAssert.AreEqual( binary.Header.Magic, newBinary.Header.Magic );
            Assert.AreEqual( binary.Header.ExtSize, newBinary.Header.ExtSize );
            Assert.AreEqual( binary.Header.RelocationTable.Offset, newBinary.Header.RelocationTable.Offset );
            CollectionAssert.AreEqual( binary.Header.RelocationTable.Value, newBinary.Header.RelocationTable.Value );
            Assert.AreEqual( binary.Header.RelocationTableSize, newBinary.Header.RelocationTableSize );
            Assert.AreEqual( binary.Header.DialogCount, newBinary.Header.DialogCount );
            Assert.AreEqual( binary.Header.IsRelocated, newBinary.Header.IsRelocated );
            Assert.AreEqual( binary.Header.Version, newBinary.Header.Version );

            for ( var index = 0; index < binary.DialogHeaders.Count; index++ )
            {
                var header = binary.DialogHeaders[index];
                var newHeader = newBinary.DialogHeaders[index];

                // compare message headers
                Assert.AreEqual( header.Kind, newHeader.Kind );
                Assert.AreEqual( header.Data.Offset, newHeader.Data.Offset );

                // compare message data
                switch ( header.Kind )
                {
                    case BinaryDialogKind.Message:
                        {
                            var dialogue = ( BinaryMessageDialog )header.Data.Value;
                            var newDialogue = ( BinaryMessageDialog )newHeader.Data.Value;

                            Assert.AreEqual( dialogue.Name, newDialogue.Name );
                            Assert.AreEqual( dialogue.PageCount, newDialogue.PageCount );
                            Assert.AreEqual( dialogue.SpeakerId, newDialogue.SpeakerId );
                            CollectionAssert.AreEqual( dialogue.PageStartAddresses, newDialogue.PageStartAddresses );
                            Assert.AreEqual( dialogue.TextBufferSize, newDialogue.TextBufferSize );
                            CollectionAssert.AreEqual( dialogue.TextBuffer, newDialogue.TextBuffer );
                        }
                        break;

                    case BinaryDialogKind.Selection:
                        {
                            var selection = ( BinarySelectionDialog )header.Data.Value;
                            var newSelection = ( BinarySelectionDialog )newHeader.Data.Value;

                            Assert.AreEqual( selection.Name, newSelection.Name );
                            Assert.AreEqual( selection.Ext, newSelection.Ext );
                            Assert.AreEqual( selection.OptionCount, newSelection.OptionCount );
                            Assert.AreEqual( selection.Pattern, newSelection.Pattern );
                            Assert.AreEqual( selection.Reserved, newSelection.Reserved );
                            CollectionAssert.AreEqual( selection.OptionStartAddresses, newSelection.OptionStartAddresses );
                            Assert.AreEqual( selection.TextBufferSize, newSelection.TextBufferSize );
                            CollectionAssert.AreEqual( selection.TextBuffer, newSelection.TextBuffer );
                        }
                        break;

                    default:
                        throw new NotImplementedException( header.Kind.ToString() );
                }
            }

            // compare speaker table header
            Assert.AreEqual( binary.SpeakerTableHeader.SpeakerNameArray.Offset, newBinary.SpeakerTableHeader.SpeakerNameArray.Offset );
            Assert.AreEqual( binary.SpeakerTableHeader.SpeakerCount, newBinary.SpeakerTableHeader.SpeakerCount );
            Assert.AreEqual( binary.SpeakerTableHeader.ExtDataOffset, newBinary.SpeakerTableHeader.ExtDataOffset );
            Assert.AreEqual( binary.SpeakerTableHeader.Reserved, newBinary.SpeakerTableHeader.Reserved );

            for ( int i = 0; i < binary.SpeakerTableHeader.SpeakerNameArray.Value.Length; i++ )
            {
                var speakername = binary.SpeakerTableHeader.SpeakerNameArray.Value[i];
                var newSpeakername = newBinary.SpeakerTableHeader.SpeakerNameArray.Value[i];

                Assert.AreEqual( speakername.Offset, newSpeakername.Offset );
                CollectionAssert.AreEqual( speakername.Value, newSpeakername.Value );
            }
        }
    }
}