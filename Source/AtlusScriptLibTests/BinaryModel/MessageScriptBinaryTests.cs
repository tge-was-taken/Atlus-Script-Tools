using System;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Linq;

namespace AtlusScriptLib.BinaryModel.Tests
{
    [TestClass()]
    public class MessageScriptBinaryTests
    {
        [TestMethod()]
        public void FromFile_ShouldPassIntegrityCheck_Version1WithUnknownVersionArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod()]
        public void FromFile_ShouldPassIntegrityCheck_Version1WithVersion1Argument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd", MessageScriptBinaryFormatVersion.Version1 );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod()]
        public void FromFile_ShouldPassIntegrityCheck_Version1WithVersion1BigEndianArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd", MessageScriptBinaryFormatVersion.Version1BigEndian );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod()]
        public void FromFile_ShouldPassIntegrityCheck_Version1BigEndianWithUnknownVersionArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd" );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod()]
        public void FromFile_ShouldPassIntegrityCheck_Version1BigEndianWithVersion1BigEndianArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd", MessageScriptBinaryFormatVersion.Version1BigEndian );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod()]
        public void FromFile_ShouldPassIntegrityCheck_Version1BigEndianWithVersion1Argument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd", MessageScriptBinaryFormatVersion.Version1 );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod()]
        public void FromFile_ShouldThrowException_NullArgument()
        {
            Assert.ThrowsException<ArgumentNullException>( () => MessageScriptBinary.FromFile( null ) );
        }

        [TestMethod()]
        public void FromFile_ShouldThrowException_EmptyStringArgument()
        {
            Assert.ThrowsException<ArgumentException>( () => MessageScriptBinary.FromFile( String.Empty ) );
        }

        [TestMethod()]
        public void FromFile_ShouldThrowException_InvalidFileFormat()
        {
            Assert.ThrowsException<InvalidDataException>( () => MessageScriptBinary.FromFile( "TestResources\\dummy_big.bin" ) );
        }

        [TestMethod()]
        public void FromFile_NoException_Batch()
        {
            foreach ( var path in Directory.EnumerateFiles( "TestResources\\Batch\\", "*.bmd" ) )
            {
                var script = MessageScriptBinary.FromFile( path );

                PrintSpeakerIdsIfHigherThanTotalSpeakers( script );

                if ( script.SpeakerTableHeader.Field08 != 0 )
                    Trace.WriteLine( $"{nameof( MessageScriptBinary )}.{nameof( script.SpeakerTableHeader )}.{nameof( script.SpeakerTableHeader.Field08 )} = {script.SpeakerTableHeader.Field08}" );

                if ( script.SpeakerTableHeader.Field0C != 0 )
                    Trace.WriteLine( $"{nameof( MessageScriptBinary )}.{nameof( script.SpeakerTableHeader )}.{nameof( script.SpeakerTableHeader.Field0C )} = {script.SpeakerTableHeader.Field0C}" );
            }
        }

        [TestMethod()]
        public void FromStream_ShouldPassIntegrityCheck_Version1()
        {
            var script = MessageScriptBinary.FromStream( File.OpenRead( "TestResources\\Version1.bmd" ) );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod()]
        public void FromStream_ShouldPassIntegrityCheck_Version1BigEndian()
        {
            var script = MessageScriptBinary.FromStream( File.OpenRead( "TestResources\\Version1BigEndian.bmd" ) );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod()]
        public void ToFile_ResultShouldPassIntegrityCheck_Version1()
        {
            try
            {
                var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
                script.ToFile( "TestResources\\Version1_ToFile.bmd" );
                script = MessageScriptBinary.FromFile( "TestResources\\Version1_ToFile.bmd" );
                PerformIntegrityCheckForVersion1( script );
            }
            finally
            {
                File.Delete( "TestResources\\Version1_ToFileTest.bmd" );
            }
        }

        [TestMethod()]
        public void ToFile_ResultShouldPassIntegrityCheck_Version1BigEndian()
        {
            try
            {
                var script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd" );
                script.ToFile( "TestResources\\Version1BigEndian_ToFile.bmd" );
                script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian_ToFile.bmd" );
                PerformIntegrityCheckForVersion1BigEndian( script );
            }
            finally
            {
                File.Delete( "TestResources\\Version1BigEndian_ToFile.bmd" );
            }
        }

        [TestMethod()]
        public void ToStream_StreamNotNullOrEmptyAndLengthEqualToFileSize_Version1()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
            var stream = script.ToStream();
            Assert.IsNotNull( stream );
            Assert.AreNotEqual( 0, stream.Length );
            Assert.AreEqual( script.Header.FileSize, stream.Length );
        }

        [TestMethod()]
        public void ToStream_StreamNotNullOrEmptyAndLengthEqualToFileSize_Version1_TakesStreamParam()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
            var stream = new MemoryStream();
            script.ToStream( stream, true );
            Assert.IsNotNull( stream );
            Assert.AreNotEqual( 0, stream.Length );
            Assert.AreEqual( script.Header.FileSize, stream.Length );
        }

        private void PrintSpeakerIdsIfHigherThanTotalSpeakers( MessageScriptBinary script )
        {
            foreach ( var messageHeader in script.MessageHeaders )
            {
                if ( messageHeader.MessageType != MessageScriptBinaryMessageType.Dialogue )
                    continue;

                var message = ( MessageScriptBinaryDialogueMessage )messageHeader.Message.Value;

                if ( ( ushort )message.SpeakerId > ( script.SpeakerTableHeader.SpeakerCount - 1 ) )
                {
                    Trace.WriteLine( $"SpeakerId: {message.SpeakerId:X4}" );
                }
            }
        }

        private void PerformIntegrityCheckForVersion1( MessageScriptBinary script )
        {
            PrintSpeakerIdsIfHigherThanTotalSpeakers( script );

            // header checks
            Assert.AreEqual( 7, script.Header.FileType );
            Assert.AreEqual( false, script.Header.IsCompressed );
            Assert.AreEqual( 0, script.Header.UserId );
            Assert.AreEqual( 0x987A, script.Header.FileSize );
            Assert.IsTrue( script.Header.Magic.SequenceEqual( MessageScriptBinaryHeader.MAGIC_V1 ) );
            Assert.AreEqual( 0, script.Header.Field0C );
            Assert.AreEqual( 0x96EC, script.Header.RelocationTable.Offset );
            Assert.AreEqual( 0x018E, script.Header.RelocationTable.Value.Length );
            Assert.AreEqual( 0x018E, script.Header.RelocationTableSize );
            Assert.AreEqual( 0x9B, script.Header.MessageCount );
            Assert.AreEqual( 0x9B, script.MessageHeaders.Count );
            Assert.AreEqual( false, script.Header.IsRelocated );
            Assert.AreEqual( 2, script.Header.Field1E );

            // check some message headers
            Assert.AreEqual( MessageScriptBinaryMessageType.Selection, script.MessageHeaders[0].MessageType );
            Assert.AreEqual( 0x04E8, script.MessageHeaders[0].Message.Offset );

            Assert.AreEqual( MessageScriptBinaryMessageType.Dialogue, script.MessageHeaders[26].MessageType );
            Assert.AreEqual( 0x1B68, script.MessageHeaders[26].Message.Offset );

            // check some messages
            Assert.AreEqual( "combine_sel", ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Identifier );
            Assert.AreEqual( 0, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Field18 );
            Assert.AreEqual( 2, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionCount );
            Assert.AreEqual( 0, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Field1C );
            Assert.AreEqual( 0, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Field1E );
            Assert.AreEqual( 2, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionStartAddresses.Length );
            Assert.AreEqual( 0x0514, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionStartAddresses[0] );
            Assert.AreEqual( 0x051E, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionStartAddresses[1] );
            Assert.AreEqual( 0x14, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).TextBufferSize );
            Assert.AreEqual( 0x14, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).TextBuffer.Length );

            Assert.AreEqual( "book_bonus004", ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).Identifier );
            Assert.AreEqual( 0x0A, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).LineCount );
            Assert.AreEqual( 0x01, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).SpeakerId );
            Assert.AreEqual( 0x0A, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).LineStartAddresses.Length );
            Assert.AreEqual( 0x1BB0, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).LineStartAddresses[0] );
            Assert.AreEqual( 0x1C1C, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).LineStartAddresses[1] );
            Assert.AreEqual( 0x02CE, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).TextBufferSize );
            Assert.AreEqual( 0x02CE, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).TextBuffer.Length );
        }

        private void PerformIntegrityCheckForVersion1BigEndian( MessageScriptBinary script )
        {
            PrintSpeakerIdsIfHigherThanTotalSpeakers( script );

            // header checks
            Assert.AreEqual( 7, script.Header.FileType );
            Assert.AreEqual( false, script.Header.IsCompressed );
            Assert.AreEqual( 0, script.Header.UserId );
            Assert.AreEqual( 0x6F89, script.Header.FileSize );
            Assert.IsTrue( script.Header.Magic.SequenceEqual( MessageScriptBinaryHeader.MAGIC_V1_BE ) );
            Assert.AreEqual( 0, script.Header.Field0C );
            Assert.AreEqual( 0x6E50, script.Header.RelocationTable.Offset );
            Assert.AreEqual( 0x0139, script.Header.RelocationTableSize );
            Assert.AreEqual( script.Header.RelocationTableSize, script.Header.RelocationTable.Value.Length );
            Assert.AreEqual( 0x76, script.Header.MessageCount );
            Assert.AreEqual( script.Header.MessageCount, script.MessageHeaders.Count );
            Assert.AreEqual( false, script.Header.IsRelocated );
            Assert.AreEqual( 2, script.Header.Field1E );

            // check some message headers
            Assert.AreEqual( MessageScriptBinaryMessageType.Selection, script.MessageHeaders[0].MessageType );
            Assert.AreEqual( 0x03C0, script.MessageHeaders[0].Message.Offset );

            Assert.AreEqual( MessageScriptBinaryMessageType.Dialogue, script.MessageHeaders[26].MessageType );
            Assert.AreEqual( 0x0F24, script.MessageHeaders[26].Message.Offset );

            // check some messages
            Assert.AreEqual( "FCL_MSG_COMBINE_SELECT", ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Identifier );
            Assert.AreEqual( 0, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Field18 );
            Assert.AreEqual( 2, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionCount );
            Assert.AreEqual( 0, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Field1C );
            Assert.AreEqual( 0, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).Field1E );
            Assert.AreEqual( 2, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionStartAddresses.Length );
            Assert.AreEqual( 0x03EC, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionStartAddresses[0] );
            Assert.AreEqual( 0x03FC, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).OptionStartAddresses[1] );
            Assert.AreEqual( 0x23, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).TextBufferSize );
            Assert.AreEqual( 0x23, ( ( MessageScriptBinarySelectionMessage )script.MessageHeaders[0].Message.Value ).TextBuffer.Length );

            Assert.AreEqual( "FCL_MSG_COMBINE_CELL_HOU", ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).Identifier );
            Assert.AreEqual( 0x01, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).LineCount );
            Assert.AreEqual( 0x01, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).SpeakerId );
            Assert.AreEqual( 0x01, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).LineStartAddresses.Length );
            Assert.AreEqual( 0x0F48, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).LineStartAddresses[0] );
            Assert.AreEqual( 0x40, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).TextBufferSize );
            Assert.AreEqual( 0x40, ( ( MessageScriptBinaryDialogueMessage )script.MessageHeaders[26].Message.Value ).TextBuffer.Length );
        }
    }
}