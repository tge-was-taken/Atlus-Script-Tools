using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLib.MessageScriptLanguage.BinaryModel.Tests
{
    [TestClass]
    public class MessageScriptBinaryTests
    {
        [TestMethod]
        public void FromFile_ShouldPassIntegrityCheck_Version1WithUnknownVersionArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod]
        public void FromFile_ShouldPassIntegrityCheck_Version1WithVersion1Argument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd", BinaryFormatVersion.Version1 );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod]
        public void FromFile_ShouldPassIntegrityCheck_Version1WithVersion1BigEndianArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd", BinaryFormatVersion.Version1BigEndian );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod]
        public void FromFile_ShouldPassIntegrityCheck_Version1BigEndianWithUnknownVersionArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd" );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod]
        public void FromFile_ShouldPassIntegrityCheck_Version1BigEndianWithVersion1BigEndianArgument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd", BinaryFormatVersion.Version1BigEndian );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod]
        public void FromFile_ShouldPassIntegrityCheck_Version1BigEndianWithVersion1Argument()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1BigEndian.bmd", BinaryFormatVersion.Version1 );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod]
        public void FromFile_ShouldThrowException_NullArgument()
        {
            Assert.ThrowsException<ArgumentNullException>( () => MessageScriptBinary.FromFile( null ) );
        }

        [TestMethod]
        public void FromFile_ShouldThrowException_EmptyStringArgument()
        {
            Assert.ThrowsException<ArgumentException>( () => MessageScriptBinary.FromFile( String.Empty ) );
        }

        [TestMethod]
        public void FromFile_ShouldThrowException_InvalidFileFormat()
        {
            Assert.ThrowsException<InvalidDataException>( () => MessageScriptBinary.FromFile( "TestResources\\dummy_big.bin" ) );
        }

        [TestMethod]
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

        [TestMethod]
        public void FromStream_ShouldPassIntegrityCheck_Version1()
        {
            var script = MessageScriptBinary.FromStream( File.OpenRead( "TestResources\\Version1.bmd" ) );
            PerformIntegrityCheckForVersion1( script );
        }

        [TestMethod]
        public void FromStream_ShouldPassIntegrityCheck_Version1BigEndian()
        {
            var script = MessageScriptBinary.FromStream( File.OpenRead( "TestResources\\Version1BigEndian.bmd" ) );
            PerformIntegrityCheckForVersion1BigEndian( script );
        }

        [TestMethod]
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

        [TestMethod]
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

        [TestMethod]
        public void ToStream_StreamNotNullOrEmptyAndLengthEqualToFileSize_Version1()
        {
            var script = MessageScriptBinary.FromFile( "TestResources\\Version1.bmd" );
            var stream = script.ToStream();
            Assert.IsNotNull( stream );
            Assert.AreNotEqual( 0, stream.Length );
            Assert.AreEqual( script.Header.FileSize, stream.Length );
        }

        [TestMethod]
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
            foreach ( var messageHeader in script.WindowHeaders )
            {
                if ( messageHeader.WindowType != BinaryWindowType.Dialogue )
                    continue;

                var message = ( BinaryDialogueWindow )messageHeader.Window.Value;

                if ( message.SpeakerId > ( script.SpeakerTableHeader.SpeakerCount - 1 ) )
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
            Assert.IsTrue( script.Header.Magic.SequenceEqual( BinaryHeader.MAGIC_V1 ) );
            Assert.AreEqual( 0, script.Header.Field0C );
            Assert.AreEqual( 0x96EC, script.Header.RelocationTable.Offset );
            Assert.AreEqual( 0x018E, script.Header.RelocationTable.Value.Length );
            Assert.AreEqual( 0x018E, script.Header.RelocationTableSize );
            Assert.AreEqual( 0x9B, script.Header.WindowCount );
            Assert.AreEqual( 0x9B, script.WindowHeaders.Count );
            Assert.AreEqual( false, script.Header.IsRelocated );
            Assert.AreEqual( 2, script.Header.Field1E );

            // check some message headers
            Assert.AreEqual( BinaryWindowType.Selection, script.WindowHeaders[0].WindowType );
            Assert.AreEqual( 0x04E8, script.WindowHeaders[0].Window.Offset );

            Assert.AreEqual( BinaryWindowType.Dialogue, script.WindowHeaders[26].WindowType );
            Assert.AreEqual( 0x1B68, script.WindowHeaders[26].Window.Offset );

            // check some messages
            Assert.AreEqual( "combine_sel", ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Identifier );
            Assert.AreEqual( 0, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Field18 );
            Assert.AreEqual( 2, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionCount );
            Assert.AreEqual( 0, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Field1C );
            Assert.AreEqual( 0, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Field1E );
            Assert.AreEqual( 2, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionStartAddresses.Length );
            Assert.AreEqual( 0x0514, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionStartAddresses[0] );
            Assert.AreEqual( 0x051E, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionStartAddresses[1] );
            Assert.AreEqual( 0x14, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).TextBufferSize );
            Assert.AreEqual( 0x14, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).TextBuffer.Length );

            Assert.AreEqual( "book_bonus004", ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).Identifier );
            Assert.AreEqual( 0x0A, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).LineCount );
            Assert.AreEqual( 0x01, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).SpeakerId );
            Assert.AreEqual( 0x0A, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).LineStartAddresses.Length );
            Assert.AreEqual( 0x1BB0, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).LineStartAddresses[0] );
            Assert.AreEqual( 0x1C1C, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).LineStartAddresses[1] );
            Assert.AreEqual( 0x02CE, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).TextBufferSize );
            Assert.AreEqual( 0x02CE, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).TextBuffer.Length );
        }

        private void PerformIntegrityCheckForVersion1BigEndian( MessageScriptBinary script )
        {
            PrintSpeakerIdsIfHigherThanTotalSpeakers( script );

            // header checks
            Assert.AreEqual( 7, script.Header.FileType );
            Assert.AreEqual( false, script.Header.IsCompressed );
            Assert.AreEqual( 0, script.Header.UserId );
            Assert.AreEqual( 0x6F89, script.Header.FileSize );
            Assert.IsTrue( script.Header.Magic.SequenceEqual( BinaryHeader.MAGIC_V1_BE ) );
            Assert.AreEqual( 0, script.Header.Field0C );
            Assert.AreEqual( 0x6E50, script.Header.RelocationTable.Offset );
            Assert.AreEqual( 0x0139, script.Header.RelocationTableSize );
            Assert.AreEqual( script.Header.RelocationTableSize, script.Header.RelocationTable.Value.Length );
            Assert.AreEqual( 0x76, script.Header.WindowCount );
            Assert.AreEqual( script.Header.WindowCount, script.WindowHeaders.Count );
            Assert.AreEqual( false, script.Header.IsRelocated );
            Assert.AreEqual( 2, script.Header.Field1E );

            // check some message headers
            Assert.AreEqual( BinaryWindowType.Selection, script.WindowHeaders[0].WindowType );
            Assert.AreEqual( 0x03C0, script.WindowHeaders[0].Window.Offset );

            Assert.AreEqual( BinaryWindowType.Dialogue, script.WindowHeaders[26].WindowType );
            Assert.AreEqual( 0x0F24, script.WindowHeaders[26].Window.Offset );

            // check some messages
            Assert.AreEqual( "FCL_MSG_COMBINE_SELECT", ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Identifier );
            Assert.AreEqual( 0, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Field18 );
            Assert.AreEqual( 2, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionCount );
            Assert.AreEqual( 0, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Field1C );
            Assert.AreEqual( 0, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).Field1E );
            Assert.AreEqual( 2, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionStartAddresses.Length );
            Assert.AreEqual( 0x03EC, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionStartAddresses[0] );
            Assert.AreEqual( 0x03FC, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).OptionStartAddresses[1] );
            Assert.AreEqual( 0x23, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).TextBufferSize );
            Assert.AreEqual( 0x23, ( ( BinarySelectionWindow )script.WindowHeaders[0].Window.Value ).TextBuffer.Length );

            Assert.AreEqual( "FCL_MSG_COMBINE_CELL_HOU", ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).Identifier );
            Assert.AreEqual( 0x01, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).LineCount );
            Assert.AreEqual( 0x01, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).SpeakerId );
            Assert.AreEqual( 0x01, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).LineStartAddresses.Length );
            Assert.AreEqual( 0x0F48, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).LineStartAddresses[0] );
            Assert.AreEqual( 0x40, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).TextBufferSize );
            Assert.AreEqual( 0x40, ( ( BinaryDialogueWindow )script.WindowHeaders[26].Window.Value ).TextBuffer.Length );
        }
    }
}