using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

namespace AtlusScriptLibrary.FlowScriptLanguage.BinaryModel.IO
{
    public sealed class FlowScriptBinaryWriter : IDisposable
    {
        private bool mDisposed;
        private long mPositionBase;
        private EndianBinaryWriter mWriter;
        private BinaryFormatVersion mVersion;

        public FlowScriptBinaryWriter( Stream stream, BinaryFormatVersion version, bool leaveOpen = false )
        {
            mPositionBase = stream.Position;
            mWriter = new EndianBinaryWriter( stream, Encoding.Default, leaveOpen, version.HasFlag( BinaryFormatVersion.BigEndian ) ? Endianness.BigEndian : Endianness.LittleEndian );
            mVersion = version;
        }

        public void WriteBinary( FlowScriptBinary binary )
        {
            WriteHeader( ref binary.mHeader );
            WriteSectionHeaders( binary.mSectionHeaders );
            for ( int i = 0; i < binary.mSectionHeaders.Length; i++ )
            {
                ref var sectionHeader = ref binary.mSectionHeaders[i];

                switch ( sectionHeader.SectionType )
                {
                    case BinarySectionType.ProcedureLabelSection:
                        WriteLabelSection( ref sectionHeader, binary.mProcedureLabelSection );
                        break;

                    case BinarySectionType.JumpLabelSection:
                        WriteLabelSection( ref sectionHeader, binary.mJumpLabelSection );
                        break;

                    case BinarySectionType.TextSection:
                        WriteTextSection( ref sectionHeader, binary.mTextSection );
                        break;

                    case BinarySectionType.MessageScriptSection:
                        WriteMessageScriptSection( ref sectionHeader, binary.mMessageScriptSection );
                        break;

                    case BinarySectionType.StringSection:
                        WriteStringSection( ref sectionHeader, binary.mStringSection );
                        break;

                    default:
                        throw new Exception( "Unknown section type" );
                }
            }
        }

        public void WriteHeader( ref BinaryHeader header )
        {
            mWriter.Write( ref header );
        }

        public void WriteSectionHeaders( BinarySectionHeader[] sectionHeaders )
        {
            mWriter.Write( sectionHeaders );
        }

        public void WriteLabelSection( ref BinarySectionHeader sectionHeader, BinaryLabel[] labels )
        {
            mWriter.SeekBegin( mPositionBase + sectionHeader.FirstElementAddress );

            foreach ( var label in labels )
            {
                int labelLength = ( mVersion.HasFlag( BinaryFormatVersion.Version1 ) ? BinaryLabel.SIZE_V1 :
                                    mVersion.HasFlag( BinaryFormatVersion.Version2 ) ? BinaryLabel.SIZE_V2 :
                                    mVersion.HasFlag( BinaryFormatVersion.Version3 ) ? BinaryLabel.SIZE_V3 :
                                    throw new Exception( "Invalid format version" ) ) - ( sizeof( int ) * 2 );

                mWriter.Write( label.Name.Substring( 0, Math.Min( label.Name.Length, labelLength ) ), 
                    StringBinaryFormat.FixedLength, labelLength );
                mWriter.Write( label.InstructionIndex );
                mWriter.Write( label.Reserved );
            }
        }

        public void WriteTextSection( ref BinarySectionHeader sectionHeader, BinaryInstruction[] instructions )
        {
            mWriter.SeekBegin( mPositionBase + sectionHeader.FirstElementAddress );

            for ( int i = 0; i < instructions.Length; i++ )
            {
                ref var instruction = ref instructions[i];

                mWriter.Write( ( short )instruction.Opcode );
                mWriter.Write( instruction.OperandShort );
                
                // Write large operands immediately afterwards
                if ( instruction.Opcode == Opcode.PUSHI )
                {
                    Trace.Assert( i + 1 < instructions.Length, "Missing operand value for PUSHI" );
                    mWriter.Write( instructions[++i].OperandInt );
                }
                else if ( instruction.Opcode == Opcode.PUSHF )
                {
                    Trace.Assert( i + 1 < instructions.Length, "Missing operand value for PUSHF" );
                    mWriter.Write( instructions[++i].OperandFloat );
                }
            }
        }

        public void WriteMessageScriptSection( ref BinarySectionHeader sectionHeader, MessageScriptBinary messageScript )
        {
            mWriter.SeekBegin( mPositionBase + sectionHeader.FirstElementAddress );
            messageScript.ToStream( mWriter.BaseStream, true );
        }

        public void WriteStringSection( ref BinarySectionHeader sectionHeader, byte[] stringSection )
        {
            mWriter.SeekBegin( mPositionBase + sectionHeader.FirstElementAddress );
            mWriter.Write( stringSection );
        }

        public void Dispose()
        {
            if ( mDisposed )
                return;

            // Dispose the writer, and thus the stream as well
            ( ( IDisposable )mWriter ).Dispose();

            mDisposed = true;
        }
    }
}
