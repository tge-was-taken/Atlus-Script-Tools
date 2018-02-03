using System;
using System.IO;
using System.Text;
using AtlusScriptLib.Common.IO;

namespace AtlusScriptLib.MessageScriptLanguage.BinaryModel.IO
{
    public sealed class MessageScriptBinaryWriter : IDisposable
    {
        private bool mDisposed;
        private readonly long mPositionBase;
        private readonly EndianBinaryWriter mWriter;

        public MessageScriptBinaryWriter( Stream stream, BinaryFormatVersion version, bool leaveOpen = false )
        {
            mPositionBase = stream.Position;
            mWriter = new EndianBinaryWriter( stream, Encoding.ASCII, leaveOpen, version.HasFlag( BinaryFormatVersion.BigEndian ) ? Endianness.BigEndian : Endianness.LittleEndian );
        }

        public void Dispose()
        {
            if ( mDisposed )
                return;

            ( ( IDisposable )mWriter ).Dispose();

            mDisposed = true;
        }

        public void WriteBinary( MessageScriptBinary binary )
        {
            WriteHeader( ref binary.mHeader );
            WriteMessageHeaders( binary.mWindowHeaders );
            WriteSpeakerHeader( ref binary.mSpeakerTableHeader );
            WriteMessages( binary.mWindowHeaders );
            WriteSpeakerNameOffsets( ref binary.mSpeakerTableHeader );
            WriteSpeakerNames( ref binary.mSpeakerTableHeader );
            WriteRelocationTable( ref binary.mHeader.RelocationTable );
        }

        private void WriteHeader( ref BinaryHeader header )
        {
            mWriter.Write( header.FileType );
            mWriter.Write( header.IsCompressed ? ( byte )1 : ( byte )0 );
            mWriter.Write( header.UserId );
            mWriter.Write( header.FileSize );
            mWriter.Write( header.Magic );
            mWriter.Write( header.Field0C );
            mWriter.Write( header.RelocationTable.Offset );
            mWriter.Write( header.RelocationTableSize );
            mWriter.Write( header.WindowCount );
            mWriter.Write( header.IsRelocated ? ( short )1 : ( short )0 );
            mWriter.Write( header.Field1E );
        }

        private void WriteMessageHeaders( BinaryWindowHeader[] messageHeaders )
        {
            foreach ( var messageHeader in messageHeaders )
            {
                mWriter.Write( ( int )messageHeader.WindowType );
                mWriter.Write( messageHeader.Window.Offset );
            }
        }

        private void WriteSpeakerHeader( ref BinarySpeakerTableHeader header )
        {
            mWriter.Write( header.SpeakerNameArray.Offset );
            mWriter.Write( header.SpeakerCount );
            mWriter.Write( header.Field08 );
            mWriter.Write( header.Field0C );
        }

        private void WriteMessages( BinaryWindowHeader[] messageHeaders )
        {
            foreach ( var messageHeader in messageHeaders )
            {
                mWriter.SeekBegin( mPositionBase + BinaryHeader.SIZE + messageHeader.Window.Offset );

                switch ( messageHeader.WindowType )
                {
                    case BinaryWindowType.Dialogue:
                        WriteDialogueMessage( ( BinaryDialogueWindow )messageHeader.Window.Value );
                        break;

                    case BinaryWindowType.Selection:
                        WriteSelectionMessage( ( BinarySelectionWindow )messageHeader.Window.Value );
                        break;

                    default:
                        throw new NotImplementedException( messageHeader.WindowType.ToString() );
                }
            }
        }

        private void WriteDialogueMessage( BinaryDialogueWindow dialogue )
        {
            mWriter.Write( dialogue.Identifier, StringBinaryFormat.FixedLength, BinaryDialogueWindow.IDENTIFIER_LENGTH );
            mWriter.Write( dialogue.LineCount );
            mWriter.Write( dialogue.SpeakerId );

            if ( dialogue.LineCount > 0 )
            {
                mWriter.Write( dialogue.LineStartAddresses );
                mWriter.Write( dialogue.TextBufferSize );
                mWriter.Write( dialogue.TextBuffer );
            }
        }

        private void WriteSelectionMessage( BinarySelectionWindow selection )
        {
            mWriter.Write( selection.Identifier, StringBinaryFormat.FixedLength, BinarySelectionWindow.IDENTIFIER_LENGTH );
            mWriter.Write( selection.Field18 );
            mWriter.Write( selection.OptionCount );
            mWriter.Write( selection.Field1C );
            mWriter.Write( selection.Field1E );
            mWriter.Write( selection.OptionStartAddresses );
            mWriter.Write( selection.TextBufferSize );
            mWriter.Write( selection.TextBuffer );
        }

        private void WriteSpeakerNameOffsets( ref BinarySpeakerTableHeader header )
        {
            mWriter.SeekBegin( mPositionBase + BinaryHeader.SIZE + header.SpeakerNameArray.Offset );
            foreach ( var speakerName in header.SpeakerNameArray.Value )
                mWriter.Write( speakerName.Offset );
        }

        private void WriteSpeakerNames( ref BinarySpeakerTableHeader header )
        {
            foreach ( var speakerName in header.SpeakerNameArray.Value )
            {
                mWriter.SeekBegin( mPositionBase + BinaryHeader.SIZE + speakerName.Offset );
                mWriter.Write( speakerName.Value.ToArray() );
                mWriter.Write( ( byte )0 );
            }
        }

        private void WriteRelocationTable( ref OffsetTo<byte[]> relocationTable )
        {
            mWriter.SeekBegin( mPositionBase + relocationTable.Offset );
            mWriter.Write( relocationTable.Value );
        }
    }
}