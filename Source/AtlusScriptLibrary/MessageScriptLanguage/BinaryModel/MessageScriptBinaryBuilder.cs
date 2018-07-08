using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.MessageScriptLanguage.IO;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel
{
    public class MessageScriptBinaryBuilder
    {
        // required
        private readonly BinaryFormatVersion mFormatVersion;

        // optional
        private short mUserId;
        private Encoding mEncoding;
        private List<Tuple<BinaryDialogKind, object>> mDialogs;

        // temporary storage
        private readonly List<int> mAddressLocations;   // for generating the relocation table
        private int mPosition;                          // used to calculate addresses
        private readonly List<byte[]> mSpeakerNames;    // for storing the speaker names of dialogue messages

        public MessageScriptBinaryBuilder( BinaryFormatVersion version )
        {
            mFormatVersion = version;
            mAddressLocations = new List<int>();
            mSpeakerNames = new List<byte[]>();
            mPosition = BinaryHeader.SIZE;
            mDialogs = new List<Tuple<BinaryDialogKind, object>>();
        }

        public void SetUserId( short value )
        {
            mUserId = value;
        }

        internal void SetEncoding( Encoding encoding )
        {
            mEncoding = encoding;
        }

        public void AddDialog( MessageDialog message )
        {
            if ( mDialogs == null )
                mDialogs = new List<Tuple<BinaryDialogKind, object>>();

            BinaryMessageDialog binary;

            binary.Name = message.Name;
            binary.PageCount = ( short )message.Pages.Count;

            if ( message.Speaker != null )
            {
                switch ( message.Speaker.Kind )
                {
                    case SpeakerKind.Named:
                        {
                            var speakerName = ProcessLine( ( ( NamedSpeaker )message.Speaker ).Name );
                            if ( !mSpeakerNames.Any( x => x.SequenceEqual( speakerName ) ) )
                                mSpeakerNames.Add( speakerName.ToArray() );

                            binary.SpeakerId = ( ushort )mSpeakerNames.FindIndex( x => x.SequenceEqual( speakerName ) );
                        }
                        break;

                    case SpeakerKind.Variable:
                        {
                            binary.SpeakerId = ( ushort )( 0x8000u | ( ( VariableSpeaker )message.Speaker ).Index );
                        }
                        break;

                    default:
                        throw new ArgumentException( nameof( message ) );
                }
            }
            else
            {
                binary.SpeakerId = 0xFFFF;
            }

            binary.PageStartAddresses = new int[message.Pages.Count];

            var textBuffer = new List<byte>();
            {
                int lineStartAddress = 0x1C + ( binary.PageCount * 4 ) + 4;

                for ( int i = 0; i < message.Pages.Count; i++ )
                {
                    binary.PageStartAddresses[i] = lineStartAddress;

                    var lineBytes = ProcessLine( message.Pages[i] );
                    textBuffer.AddRange( lineBytes );

                    lineStartAddress += lineBytes.Count;
                }

                textBuffer.Add( 0 );
            }

            binary.TextBuffer = textBuffer.ToArray();
            binary.TextBufferSize = binary.TextBuffer.Length;

            mDialogs.Add( new Tuple<BinaryDialogKind, object>( BinaryDialogKind.Message, binary ) );
        }

        public void AddDialog( SelectionDialog message )
        {
            if ( mDialogs == null )
                mDialogs = new List<Tuple<BinaryDialogKind, object>>();

            BinarySelectionDialog binary;

            binary.Name = message.Name;
            binary.Field18 = binary.Field1C = binary.Field1E = 0;
            binary.OptionCount = ( short )message.Options.Count;
            binary.OptionStartAddresses = new int[message.Options.Count];

            var textBuffer = new List<byte>();
            {
                int lineStartAddress = 0x20 + ( binary.OptionCount * 4 ) + 4;
                for ( int i = 0; i < message.Options.Count; i++ )
                {
                    binary.OptionStartAddresses[i] = lineStartAddress;

                    var lineBytes = ProcessLine( message.Options[i] );
                    lineBytes.Add( 0 ); // intentional

                    textBuffer.AddRange( lineBytes );

                    lineStartAddress += lineBytes.Count;
                }

                textBuffer.Add( 0 ); // intentional
            }

            binary.TextBuffer = textBuffer.ToArray();
            binary.TextBufferSize = binary.TextBuffer.Length;

            mDialogs.Add( new Tuple<BinaryDialogKind, object>( BinaryDialogKind.Selection, binary ) );
        }

        public MessageScriptBinary Build()
        {
            var binary = new MessageScriptBinary
            {
                mFormatVersion = mFormatVersion
            };

            // note: DONT CHANGE THE ORDER
            BuildHeaderFirstPass( ref binary.mHeader );

            if ( mDialogs != null )
            {
                BuildWindowHeadersFirstPass( ref binary.mDialogHeaders );

                BuildSpeakerTableHeaderFirstPass( ref binary.mSpeakerTableHeader );

                BuildWindowHeadersFinalPass( ref binary.mDialogHeaders );

                BuildSpeakerTableHeaderSecondPass( ref binary.mSpeakerTableHeader );

                BuildSpeakerTableHeaderFinalPass( ref binary.mSpeakerTableHeader );
            }

            BuildHeaderFinalPass( ref binary.mHeader );

            return binary;
        }

        private List<byte> ProcessLine( TokenText line )
        {
            List<byte> bytes = new List<byte>();

            foreach ( var token in line.Tokens )
            {
                ProcessToken( token, bytes );
            }

            return bytes;
        }

        private void ProcessToken( IToken token, List<byte> bytes )
        {
            switch ( token.Kind )
            {
                case TokenKind.String:
                    ProcessTextToken( ( StringToken )token, bytes );
                    break;

                case TokenKind.Function:
                    ProcessFunctionToken( ( FunctionToken )token, bytes );
                    break;

                case TokenKind.CodePoint:
                    ProcessCodePoint( ( CodePointToken )token, bytes );
                    break;

                case TokenKind.NewLine:
                    bytes.Add( NewLineToken.Value );
                    break;

                default:
                    throw new NotImplementedException( token.Kind.ToString() );
            }
        }

        private void ProcessTextToken( StringToken token, List<byte> bytes )
        {
            byte[] textBytes;
            if ( mEncoding != null )
            {
                textBytes = mEncoding.GetBytes( token.Value );
            }
            else
            {
                textBytes = Encoding.ASCII.GetBytes( token.Value );
            }

            // simple add to the list of bytes
            bytes.AddRange( textBytes );
        }

        private void ProcessFunctionToken( FunctionToken token, List<byte> bytes )
        {
            // AAAA BBBB where A is a signifier value for a function and B is the encoded argument byte size
            byte functionSignifier;

            if ( mFormatVersion.HasFlag( BinaryFormatVersion.Version1 ) )
            {
                functionSignifier = ( byte ) ( 0xF0 | ( ( ( token.Arguments.Count * sizeof( short ) ) / 2 ) + 1 ) & 0x0F );
            }
            else if ( mFormatVersion == BinaryFormatVersion.Version1DDS )
            {
                byte argumentByteCount = ( byte ) ( ( token.Arguments.Count * 2 ) & 0x0F );
                if ( argumentByteCount == 0 )
                    argumentByteCount = 1; // tested

                functionSignifier = ( byte ) ( 0xF0 | argumentByteCount );
            }
            else
            {
                throw new NotImplementedException( mFormatVersion.ToString() );
            }

            // AAAB BBBB where A is the table index and B is the function index
            byte functionId = ( byte )( ( ( token.FunctionTableIndex & 0x07 ) << 5 ) | token.FunctionIndex & 0x1F );

            byte[] argumentBytes = new byte[token.Arguments.Count * 2];

            for ( int i = 0; i < token.Arguments.Count; i++ )
            {
                // arguments are stored in little endian regardless of the rest of the format
                byte firstByte = ( byte )( ( token.Arguments[i] & 0xFF ) + 1 );
                byte secondByte = ( byte )( ( ( token.Arguments[i] & 0xFF00 ) >> 8 ) + 1 );

                int byteIndex = i * sizeof( short );
                argumentBytes[byteIndex] = firstByte;
                argumentBytes[byteIndex + 1] = secondByte;
            }

            bytes.Add( functionSignifier );
            bytes.Add( functionId );
            bytes.AddRange( argumentBytes );
        }

        private void ProcessCodePoint( CodePointToken token, List<byte> bytes )
        {
            bytes.Add( token.HighSurrogate );
            bytes.Add( token.LowSurrogate );
        }

        private void BuildHeaderFirstPass( ref BinaryHeader header )
        {
            header.FileType = BinaryHeader.FILE_TYPE;
            header.IsCompressed = false;
            header.UserId = mUserId;
            header.Magic = mFormatVersion.HasFlag( BinaryFormatVersion.BigEndian )
                ? BinaryHeader.MAGIC_V1_BE
                : BinaryHeader.MAGIC_V1;
            header.Field0C = 0;
            header.DialogCount = mDialogs?.Count ?? 0;
            header.IsRelocated = false;
            header.Field1E = 2;
        }

        private void BuildWindowHeadersFirstPass( ref BinaryDialogHeader[] headers )
        {
            headers = new BinaryDialogHeader[mDialogs.Count];
            for ( int i = 0; i < headers.Length; i++ )
            {
                headers[i].DialogKind = mDialogs[i].Item1;
                MoveToNextIntPosition();

                AddAddressLocation();
                MoveToNextIntPosition();
            }
        }

        private void BuildSpeakerTableHeaderFirstPass( ref BinarySpeakerTableHeader speakerHeader )
        {
            AddAddressLocation();
            MoveToNextIntPosition();

            speakerHeader.SpeakerCount = mSpeakerNames.Count;
            MoveToNextIntPosition();

            speakerHeader.Field08 = 0;
            MoveToNextIntPosition();

            speakerHeader.Field0C = 0;
            MoveToNextIntPosition();
        }

        private void BuildWindowHeadersFinalPass( ref BinaryDialogHeader[] headers )
        {
            for ( int i = 0; i < headers.Length; i++ )
            {
                headers[i].Dialog.Offset = GetAlignedAddress();
                headers[i].Dialog.Value = UpdateDialogAddressBase( mDialogs[i].Item2 );
            }
        }

        private void BuildSpeakerTableHeaderSecondPass( ref BinarySpeakerTableHeader speakerTableHeader )
        {
            speakerTableHeader.SpeakerNameArray.Offset = GetAlignedAddress();
            for ( int i = 0; i < speakerTableHeader.SpeakerCount; i++ )
            {
                AddAddressLocation();
                MoveToNextIntPosition();
            }
        }

        private void BuildSpeakerTableHeaderFinalPass( ref BinarySpeakerTableHeader speakerTableHeader )
        {
            speakerTableHeader.SpeakerNameArray.Value = new OffsetTo<List<byte>>[speakerTableHeader.SpeakerCount];
            for ( int i = 0; i < speakerTableHeader.SpeakerNameArray.Value.Length; i++ )
            {
                speakerTableHeader.SpeakerNameArray.Value[i].Offset = GetAddress();
                speakerTableHeader.SpeakerNameArray.Value[i].Value = mSpeakerNames[i].ToList();

                // todo: maybe the speakername should include the trailing 0
                MoveToNextPositionByOffset( mSpeakerNames[i].Length + 1 );
            }
        }

        private void BuildHeaderFinalPass( ref BinaryHeader header )
        {
            header.RelocationTable.Offset = GetAlignedAddress() + BinaryHeader.SIZE;
            header.RelocationTable.Value =
                RelocationTableEncoding.Encode( mAddressLocations, BinaryHeader.SIZE );
            header.RelocationTableSize = header.RelocationTable.Value.Length;
            mPosition += header.RelocationTableSize;

            header.FileSize = mPosition;
        }

        private object UpdateDialogAddressBase( object dialog )
        {
            int dialogAddress = GetAddress();

            switch ( dialog )
            {
                case BinaryMessageDialog dialogue:
                    {
                        mPosition += 0x1C;

                        for ( int i = 0; i < dialogue.PageStartAddresses.Length; i++ )
                        {
                            AddAddressLocation();
                            dialogue.PageStartAddresses[i] += dialogAddress;
                            mPosition += 4;
                        }

                        mPosition += 4 + dialogue.TextBufferSize;
                    }
                    break;

                case BinarySelectionDialog selection:
                    {
                        mPosition += 0x20;

                        for ( int i = 0; i < selection.OptionStartAddresses.Length; i++ )
                        {
                            AddAddressLocation();
                            selection.OptionStartAddresses[i] += dialogAddress;
                            mPosition += 4;
                        }

                        mPosition += 4 + selection.TextBufferSize;
                    }
                    break;

                default:
                    throw new NotImplementedException( dialog.GetType().ToString() );
            }

            return dialog;
        }

        private void MoveToNextIntPosition()
        {
            mPosition += sizeof( int );
        }

        private void MoveToNextPositionByOffset( int offset )
        {
            mPosition += offset;
        }

        private void AddAddressLocation()
        {
            mAddressLocations.Add( mPosition );
        }

        private void AlignPosition()
        {
            mPosition = ( mPosition + 3 ) & ~3;
        }

        private int GetAddress()
        {
            return mPosition - BinaryHeader.SIZE;
        }

        private int GetAlignedAddress()
        {
            AlignPosition();
            return GetAddress();
        }
    }
}
