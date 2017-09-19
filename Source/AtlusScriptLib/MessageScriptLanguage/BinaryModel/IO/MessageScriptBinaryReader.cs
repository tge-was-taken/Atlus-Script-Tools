using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using AtlusScriptLib.Common.IO;

namespace AtlusScriptLib.MessageScriptLanguage.BinaryModel.IO
{
    public sealed class MessageScriptBinaryReader : IDisposable
    {
        private bool mDisposed;
        private long mPositionBase;
        private EndianBinaryReader mReader;
        private MessageScriptBinaryFormatVersion mVersion;

        public MessageScriptBinaryReader( Stream stream, MessageScriptBinaryFormatVersion version, bool leaveOpen = false )
        {
            mPositionBase = stream.Position;
            mReader = new EndianBinaryReader( stream, Encoding.Default, leaveOpen, version.HasFlag( MessageScriptBinaryFormatVersion.BigEndian ) ? Endianness.BigEndian : Endianness.LittleEndian );
            mVersion = version;
        }

        public MessageScriptBinary ReadBinary()
        {
            var binary = new MessageScriptBinary
            {
                mHeader = ReadHeader()
            };

            binary.mWindowHeaders = ReadMessageHeaders( binary.mHeader.WindowCount );
            binary.mSpeakerTableHeader = ReadSpeakerTableHeader();
            binary.mFormatVersion = mVersion;

            return binary;
        }

        public MessageScriptBinaryHeader ReadHeader()
        {
            MessageScriptBinaryHeader header = new MessageScriptBinaryHeader();

            // Check if the stream isn't too small to be a proper file
            if ( mReader.BaseStreamLength < MessageScriptBinaryHeader.SIZE )
            {
                throw new InvalidDataException( "Stream is too small to be valid" );
            }
            else
            {
                header.FileType = mReader.ReadByte();
                header.IsCompressed = mReader.ReadByte() != 0;
                header.UserId = mReader.ReadInt16();
                header.FileSize = mReader.ReadInt32();
                header.Magic = mReader.ReadBytes( 4 );
                header.Field0C = mReader.ReadInt32();
                header.RelocationTable.Offset = mReader.ReadInt32();
                header.RelocationTableSize = mReader.ReadInt32();
                header.WindowCount = mReader.ReadInt32();
                header.IsRelocated = mReader.ReadInt16() != 0;
                header.Field1E = mReader.ReadInt16();

                // swap endianness
                if ( header.Magic.SequenceEqual( MessageScriptBinaryHeader.MAGIC_V1 ) || header.Magic.SequenceEqual( MessageScriptBinaryHeader.MAGIC_V0 ) )
                {
                    if ( mVersion.HasFlag( MessageScriptBinaryFormatVersion.BigEndian ) )
                    {
                        SwapHeader( ref header );
                        mReader.Endianness = Endianness.LittleEndian;
                    }

                    mVersion = MessageScriptBinaryFormatVersion.Version1;
                }
                else if ( header.Magic.SequenceEqual( MessageScriptBinaryHeader.MAGIC_V1_BE ) )
                {
                    if ( !mVersion.HasFlag( MessageScriptBinaryFormatVersion.BigEndian ) )
                    {
                        SwapHeader( ref header );
                        mReader.Endianness = Endianness.BigEndian;
                    }

                    mVersion = MessageScriptBinaryFormatVersion.Version1BigEndian;
                }
                else
                {
                    throw new InvalidDataException( "Header magic value does not match" );
                }

                if ( header.RelocationTable.Offset != 0 )
                {
                    mReader.EnqueuePositionAndSeekBegin( mPositionBase + header.RelocationTable.Offset );
                    header.RelocationTable.Value = mReader.ReadBytes( header.RelocationTableSize );
                    mReader.SeekBeginToDequedPosition();
                }
            }

            return header;
        }

        private void SwapHeader( ref MessageScriptBinaryHeader header )
        {
            EndiannessHelper.Swap( ref header.UserId );
            EndiannessHelper.Swap( ref header.FileSize );
            EndiannessHelper.Swap( ref header.Field0C );
            EndiannessHelper.Swap( ref header.RelocationTable.Offset );
            EndiannessHelper.Swap( ref header.RelocationTableSize );
            EndiannessHelper.Swap( ref header.WindowCount );
            EndiannessHelper.Swap( ref header.Field1E );
        }

        public MessageScriptBinaryWindowHeader[] ReadMessageHeaders( int count )
        {
            MessageScriptBinaryWindowHeader[] messageHeaders = new MessageScriptBinaryWindowHeader[count];

            for ( int i = 0; i < messageHeaders.Length; i++ )
            {
                ref var messageHeader = ref messageHeaders[i];
                messageHeader.WindowType = ( MessageScriptBinaryWindowType )mReader.ReadInt32();
                messageHeader.Window.Offset = mReader.ReadInt32();

                if ( messageHeader.Window.Offset != 0 )
                    messageHeader.Window.Value = ReadMessage( messageHeader.WindowType, messageHeader.Window.Offset );
            }

            return messageHeaders;
        }

        public MessageScriptBinarySpeakerTableHeader ReadSpeakerTableHeader()
        {
            MessageScriptBinarySpeakerTableHeader header;

            header.SpeakerNameArray.Offset = mReader.ReadInt32();
            header.SpeakerCount = mReader.ReadInt32();
            header.Field08 = mReader.ReadInt32();
            header.Field0C = mReader.ReadInt32();

            if ( header.SpeakerNameArray.Offset != 0 )
                header.SpeakerNameArray.Value = ReadSpeakerNames( header.SpeakerNameArray.Offset, header.SpeakerCount );
            else
                header.SpeakerNameArray.Value = null;

            if ( header.Field08 != 0 )
                Debug.WriteLine( $"{nameof( MessageScriptBinarySpeakerTableHeader )}.{nameof( header.Field08 )} = {header.Field08}" );

            if ( header.Field0C != 0 )
                Debug.WriteLine( $"{nameof( MessageScriptBinarySpeakerTableHeader )}.{nameof( header.Field0C )} = {header.Field0C}" );

            return header;
        }

        public OffsetTo<List<byte>>[] ReadSpeakerNames( int address, int count )
        {
            mReader.SeekBegin( mPositionBase + MessageScriptBinaryHeader.SIZE + address );

            var speakerNameAddresses = mReader.ReadInt32s( count );
            var speakerNames = new OffsetTo<List<byte>>[count];

            for ( int i = 0; i < speakerNameAddresses.Length; i++ )
            {
                ref int speakerNameAddress = ref speakerNameAddresses[i];

                mReader.SeekBegin( mPositionBase + MessageScriptBinaryHeader.SIZE + speakerNameAddress );
                var bytes = new List<byte>();
                while ( true )
                {
                    byte b = mReader.ReadByte();
                    if ( b == 0 )
                        break;

                    bytes.Add( b );
                }

                speakerNames[i] = new OffsetTo<List<byte>>( speakerNameAddress, bytes );
            }

            return speakerNames;
        }

        private object ReadMessage( MessageScriptBinaryWindowType type, int address )
        {
            object message;

            mReader.EnqueuePositionAndSeekBegin( mPositionBase + MessageScriptBinaryHeader.SIZE + address );

            switch ( type )
            {
                case MessageScriptBinaryWindowType.Dialogue:
                    message = ReadDialogueMessage();
                    break;

                case MessageScriptBinaryWindowType.Selection:
                    message = ReadSelectionMessage();
                    break;

                default:
                    throw new InvalidDataException( $"Unknown message type: {type}" );
            }

            mReader.SeekBeginToDequedPosition();

            return message;
        }

        public MessageScriptBinaryDialogueWindow ReadDialogueMessage()
        {
            MessageScriptBinaryDialogueWindow message;

            message.Identifier = mReader.ReadString( StringBinaryFormat.FixedLength, MessageScriptBinaryDialogueWindow.IDENTIFIER_LENGTH );
            message.LineCount = mReader.ReadInt16();
            message.SpeakerId = mReader.ReadUInt16();

            if ( message.LineCount > 0 )
            {
                message.LineStartAddresses = mReader.ReadInt32s( message.LineCount );
                message.TextBufferSize = mReader.ReadInt32();
                message.TextBuffer = mReader.ReadBytes( message.TextBufferSize );
            }
            else
            {
                message.LineStartAddresses = null;
                message.TextBufferSize = 0;
                message.TextBuffer = null;
            }

            return message;
        }

        public MessageScriptBinarySelectionWindow ReadSelectionMessage()
        {
            MessageScriptBinarySelectionWindow message;

            message.Identifier = mReader.ReadString( StringBinaryFormat.FixedLength, MessageScriptBinaryDialogueWindow.IDENTIFIER_LENGTH );
            message.Field18 = mReader.ReadInt16();
            message.OptionCount = mReader.ReadInt16();
            message.Field1C = mReader.ReadInt16();
            message.Field1E = mReader.ReadInt16();
            message.OptionStartAddresses = mReader.ReadInt32s( message.OptionCount );
            message.TextBufferSize = mReader.ReadInt32();
            message.TextBuffer = mReader.ReadBytes( message.TextBufferSize );

            if ( message.Field18 != 0 )
                Debug.WriteLine( $"{nameof( MessageScriptBinarySelectionWindow )}.{nameof( message.Field18 )} = {message.Field18}" );

            if ( message.Field1C != 0 )
                Debug.WriteLine( $"{nameof( MessageScriptBinarySelectionWindow )}.{nameof( message.Field1C )} = {message.Field1C}" );

            if ( message.Field1E != 0 )
                Debug.WriteLine( $"{nameof( MessageScriptBinarySelectionWindow )}.{nameof( message.Field1E )} = {message.Field1E}" );

            return message;
        }

        public void Dispose()
        {
            if ( mDisposed )
                return;

            mReader.Dispose();

            mDisposed = true;
        }
    }
}
