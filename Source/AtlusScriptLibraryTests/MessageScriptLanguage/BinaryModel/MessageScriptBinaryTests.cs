using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.Tests
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
        [Ignore]
        public void FromFile_NoException_Batch()
        {
            foreach ( var path in Directory.EnumerateFiles( "TestResources\\Batch\\", "*.bmd" ) )
            {
                var script = MessageScriptBinary.FromFile( path );

                PrintSpeakerIdsIfHigherThanTotalSpeakers( script );

                if ( script.SpeakerTableHeader.ExtDataOffset != 0 )
                    Trace.WriteLine( $"{nameof( MessageScriptBinary )}.{nameof( script.SpeakerTableHeader )}.{nameof( script.SpeakerTableHeader.ExtDataOffset )} = {script.SpeakerTableHeader.ExtDataOffset}" );

                if ( script.SpeakerTableHeader.Reserved != 0 )
                    Trace.WriteLine( $"{nameof( MessageScriptBinary )}.{nameof( script.SpeakerTableHeader )}.{nameof( script.SpeakerTableHeader.Reserved )} = {script.SpeakerTableHeader.Reserved}" );
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
            foreach ( var messageHeader in script.DialogHeaders )
            {
                if ( messageHeader.Kind != BinaryDialogKind.Message )
                    continue;

                var message = ( BinaryMessageDialog )messageHeader.Data.Value;

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
            Assert.AreEqual( 0, script.Header.Format );
            Assert.AreEqual( 0, script.Header.UserId );
            Assert.AreEqual( 0x987A, script.Header.FileSize );
            Assert.IsTrue( script.Header.Magic.SequenceEqual( BinaryHeader.MAGIC_V1 ) );
            Assert.AreEqual( 0, script.Header.ExtSize );
            Assert.AreEqual( 0x96EC, script.Header.RelocationTable.Offset );
            Assert.AreEqual( 0x018E, script.Header.RelocationTable.Value.Length );
            Assert.AreEqual( 0x018E, script.Header.RelocationTableSize );
            Assert.AreEqual( 0x9B, script.Header.DialogCount );
            Assert.AreEqual( 0x9B, script.DialogHeaders.Count );
            Assert.AreEqual( false, script.Header.IsRelocated );
            Assert.AreEqual( 2, script.Header.Version );

            // check some message headers
            Assert.AreEqual( BinaryDialogKind.Selection, script.DialogHeaders[0].Kind );
            Assert.AreEqual( 0x04E8, script.DialogHeaders[0].Data.Offset );

            Assert.AreEqual( BinaryDialogKind.Message, script.DialogHeaders[26].Kind );
            Assert.AreEqual( 0x1B68, script.DialogHeaders[26].Data.Offset );

            // check some messages
            Assert.AreEqual( "combine_sel", ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Name );
            Assert.AreEqual( 0, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Ext );
            Assert.AreEqual( 2, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionCount );
            Assert.AreEqual( BinarySelectionDialogPattern.Top, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Pattern );
            Assert.AreEqual( 0, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Reserved );
            Assert.AreEqual( 2, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionStartAddresses.Length );
            Assert.AreEqual( 0x0514, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionStartAddresses[0] );
            Assert.AreEqual( 0x051E, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionStartAddresses[1] );
            Assert.AreEqual( 0x14, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).TextBufferSize );
            Assert.AreEqual( 0x14, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).TextBuffer.Length );

            Assert.AreEqual( "book_bonus004", ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).Name );
            Assert.AreEqual( 0x0A, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).PageCount );
            Assert.AreEqual( 0x01, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).SpeakerId );
            Assert.AreEqual( 0x0A, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).PageStartAddresses.Length );
            Assert.AreEqual( 0x1BB0, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).PageStartAddresses[0] );
            Assert.AreEqual( 0x1C1C, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).PageStartAddresses[1] );
            Assert.AreEqual( 0x02CE, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).TextBufferSize );
            Assert.AreEqual( 0x02CE, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).TextBuffer.Length );
        }

        private void PerformIntegrityCheckForVersion1BigEndian( MessageScriptBinary script )
        {
            PrintSpeakerIdsIfHigherThanTotalSpeakers( script );

            // header checks
            Assert.AreEqual( 7, script.Header.FileType );
            Assert.AreEqual( 0, script.Header.Format );
            Assert.AreEqual( 0, script.Header.UserId );
            Assert.AreEqual( 0x6F89, script.Header.FileSize );
            Assert.IsTrue( script.Header.Magic.SequenceEqual( BinaryHeader.MAGIC_V1_BE ) );
            Assert.AreEqual( 0, script.Header.ExtSize );
            Assert.AreEqual( 0x6E50, script.Header.RelocationTable.Offset );
            Assert.AreEqual( 0x0139, script.Header.RelocationTableSize );
            Assert.AreEqual( script.Header.RelocationTableSize, script.Header.RelocationTable.Value.Length );
            Assert.AreEqual( 0x76, script.Header.DialogCount );
            Assert.AreEqual( script.Header.DialogCount, script.DialogHeaders.Count );
            Assert.AreEqual( false, script.Header.IsRelocated );
            Assert.AreEqual( 2, script.Header.Version );

            // check some message headers
            Assert.AreEqual( BinaryDialogKind.Selection, script.DialogHeaders[0].Kind );
            Assert.AreEqual( 0x03C0, script.DialogHeaders[0].Data.Offset );

            Assert.AreEqual( BinaryDialogKind.Message, script.DialogHeaders[26].Kind );
            Assert.AreEqual( 0x0F24, script.DialogHeaders[26].Data.Offset );

            // check some messages
            Assert.AreEqual( "FCL_MSG_COMBINE_SELECT", ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Name );
            Assert.AreEqual( 0, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Ext );
            Assert.AreEqual( 2, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionCount );
            Assert.AreEqual( BinarySelectionDialogPattern.Top, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Pattern );
            Assert.AreEqual( BinarySelectionDialogPattern.Top, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).Pattern );
            Assert.AreEqual( 2, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionStartAddresses.Length );
            Assert.AreEqual( 0x03EC, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionStartAddresses[0] );
            Assert.AreEqual( 0x03FC, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).OptionStartAddresses[1] );
            Assert.AreEqual( 0x23, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).TextBufferSize );
            Assert.AreEqual( 0x23, ( ( BinarySelectionDialog )script.DialogHeaders[0].Data.Value ).TextBuffer.Length );

            Assert.AreEqual( "FCL_MSG_COMBINE_CELL_HOU", ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).Name );
            Assert.AreEqual( 0x01, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).PageCount );
            Assert.AreEqual( 0x01, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).SpeakerId );
            Assert.AreEqual( 0x01, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).PageStartAddresses.Length );
            Assert.AreEqual( 0x0F48, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).PageStartAddresses[0] );
            Assert.AreEqual( 0x40, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).TextBufferSize );
            Assert.AreEqual( 0x40, ( ( BinaryMessageDialog )script.DialogHeaders[26].Data.Value ).TextBuffer.Length );
        }
    }
}