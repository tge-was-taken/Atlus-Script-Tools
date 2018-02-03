using System;
using System.IO;
using AtlusScriptLib.MessageScriptLanguage.BinaryModel;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLib.MessageScriptLanguage.Tests
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
            Assert.AreEqual( 0, script.Windows.Count );
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
            Assert.AreEqual( binary.Header.IsCompressed, newBinary.Header.IsCompressed );
            Assert.AreEqual( binary.Header.UserId, newBinary.Header.UserId );
            Assert.AreEqual( binary.Header.FileSize, newBinary.Header.FileSize );
            CollectionAssert.AreEqual( binary.Header.Magic, newBinary.Header.Magic );
            Assert.AreEqual( binary.Header.Field0C, newBinary.Header.Field0C );
            Assert.AreEqual( binary.Header.RelocationTable.Offset, newBinary.Header.RelocationTable.Offset );
            CollectionAssert.AreEqual( binary.Header.RelocationTable.Value, newBinary.Header.RelocationTable.Value );
            Assert.AreEqual( binary.Header.RelocationTableSize, newBinary.Header.RelocationTableSize );
            Assert.AreEqual( binary.Header.WindowCount, newBinary.Header.WindowCount );
            Assert.AreEqual( binary.Header.IsRelocated, newBinary.Header.IsRelocated );
            Assert.AreEqual( binary.Header.Field1E, newBinary.Header.Field1E );

            for ( var index = 0; index < binary.WindowHeaders.Count; index++ )
            {
                var header = binary.WindowHeaders[index];
                var newHeader = newBinary.WindowHeaders[index];

                // compare message headers
                Assert.AreEqual( header.WindowType, newHeader.WindowType );
                Assert.AreEqual( header.Window.Offset, newHeader.Window.Offset );

                // compare message data
                switch ( header.WindowType )
                {
                    case BinaryWindowType.Dialogue:
                        {
                            var dialogue = ( BinaryDialogueWindow )header.Window.Value;
                            var newDialogue = ( BinaryDialogueWindow )newHeader.Window.Value;

                            Assert.AreEqual( dialogue.Identifier, newDialogue.Identifier );
                            Assert.AreEqual( dialogue.LineCount, newDialogue.LineCount );
                            Assert.AreEqual( dialogue.SpeakerId, newDialogue.SpeakerId );
                            CollectionAssert.AreEqual( dialogue.LineStartAddresses, newDialogue.LineStartAddresses );
                            Assert.AreEqual( dialogue.TextBufferSize, newDialogue.TextBufferSize );
                            CollectionAssert.AreEqual( dialogue.TextBuffer, newDialogue.TextBuffer );
                        }
                        break;

                    case BinaryWindowType.Selection:
                        {
                            var selection = ( BinarySelectionWindow )header.Window.Value;
                            var newSelection = ( BinarySelectionWindow )newHeader.Window.Value;

                            Assert.AreEqual( selection.Identifier, newSelection.Identifier );
                            Assert.AreEqual( selection.Field18, newSelection.Field18 );
                            Assert.AreEqual( selection.OptionCount, newSelection.OptionCount );
                            Assert.AreEqual( selection.Field1C, newSelection.Field1C );
                            Assert.AreEqual( selection.Field1E, newSelection.Field1E );
                            CollectionAssert.AreEqual( selection.OptionStartAddresses, newSelection.OptionStartAddresses );
                            Assert.AreEqual( selection.TextBufferSize, newSelection.TextBufferSize );
                            CollectionAssert.AreEqual( selection.TextBuffer, newSelection.TextBuffer );
                        }
                        break;

                    default:
                        throw new NotImplementedException( header.WindowType.ToString() );
                }
            }

            // compare speaker table header
            Assert.AreEqual( binary.SpeakerTableHeader.SpeakerNameArray.Offset, newBinary.SpeakerTableHeader.SpeakerNameArray.Offset );
            Assert.AreEqual( binary.SpeakerTableHeader.SpeakerCount, newBinary.SpeakerTableHeader.SpeakerCount );
            Assert.AreEqual( binary.SpeakerTableHeader.Field08, newBinary.SpeakerTableHeader.Field08 );
            Assert.AreEqual( binary.SpeakerTableHeader.Field0C, newBinary.SpeakerTableHeader.Field0C );

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