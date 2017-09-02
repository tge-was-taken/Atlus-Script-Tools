using System;
using System.IO;
using AtlusScriptLib.IO;

namespace AtlusScriptLib.BinaryModel.IO
{
    public sealed class FlowScriptBinaryWriter : IDisposable
    {
        private bool mDisposed;
        private long mPositionBase;
        private EndianBinaryWriter mWriter;
        private FlowScriptBinaryFormatVersion mVersion;

        public FlowScriptBinaryWriter( Stream stream, FlowScriptBinaryFormatVersion version )
        {
            mPositionBase = stream.Position;
            mWriter = new EndianBinaryWriter( stream, version.HasFlag( FlowScriptBinaryFormatVersion.BigEndian ) ? Endianness.BigEndian : Endianness.LittleEndian );
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
                    case FlowScriptBinarySectionType.ProcedureLabelSection:
                        WriteLabelSection( ref sectionHeader, binary.mProcedureLabelSection );
                        break;

                    case FlowScriptBinarySectionType.JumpLabelSection:
                        WriteLabelSection( ref sectionHeader, binary.mJumpLabelSection );
                        break;

                    case FlowScriptBinarySectionType.TextSection:
                        WriteTextSection( ref sectionHeader, binary.mTextSection );
                        break;

                    case FlowScriptBinarySectionType.MessageScriptSection:
                        WriteMessageScriptSection( ref sectionHeader, binary.mMessageScriptSection );
                        break;

                    case FlowScriptBinarySectionType.StringSection:
                        WriteStringSection( ref sectionHeader, binary.mStringSection );
                        break;

                    default:
                        throw new Exception( "Unknown section type" );
                }
            }
        }

        public void WriteHeader( ref FlowScriptBinaryHeader header )
        {
            mWriter.Write( ref header );
        }

        public void WriteSectionHeaders( FlowScriptBinarySectionHeader[] sectionHeaders )
        {
            mWriter.Write( sectionHeaders );
        }

        public void WriteLabelSection( ref FlowScriptBinarySectionHeader sectionHeader, FlowScriptBinaryLabel[] labels )
        {
            mWriter.SeekBegin( mPositionBase + sectionHeader.FirstElementAddress );

            foreach ( var label in labels )
            {
                mWriter.Write( label.Name, StringBinaryFormat.FixedLength,
                    ( mVersion.HasFlag( FlowScriptBinaryFormatVersion.Version1 ) ? FlowScriptBinaryLabel.SIZE_V1 :
                    mVersion.HasFlag( FlowScriptBinaryFormatVersion.Version2 ) ? FlowScriptBinaryLabel.SIZE_V2 :
                    mVersion.HasFlag( FlowScriptBinaryFormatVersion.Version3 ) ? FlowScriptBinaryLabel.SIZE_V3 :
                    throw new Exception( "Invalid format version" ) ) - ( sizeof( int ) * 2 ) );

                mWriter.Write( label.InstructionIndex );
                mWriter.Write( label.Reserved );
            }
        }

        public void WriteTextSection( ref FlowScriptBinarySectionHeader sectionHeader, FlowScriptBinaryInstruction[] instructions )
        {
            mWriter.SeekBegin( mPositionBase + sectionHeader.FirstElementAddress );

            for ( int i = 0; i < instructions.Length; i++ )
            {
                ref var instruction = ref instructions[i];

                if ( i != 0 )
                {
                    ref var prevInstruction = ref instructions[i - 1];

                    if ( prevInstruction.Opcode == FlowScriptOpcode.PUSHI && ( prevInstruction.OperandInt == 0 && instruction.OperandInt > 0 ) )
                    {
                        mWriter.Write( instruction.OperandInt );
                        continue;
                    }
                    else if ( prevInstruction.Opcode == FlowScriptOpcode.PUSHF && ( prevInstruction.OperandFloat == 0 && instruction.OperandFloat > 0 ) )
                    {
                        mWriter.Write( instruction.OperandFloat );
                        continue;
                    }
                }

                mWriter.Write( ( short )instruction.Opcode );
                mWriter.Write( instruction.OperandShort );
            }
        }

        public void WriteMessageScriptSection( ref FlowScriptBinarySectionHeader sectionHeader, MessageScriptBinary messageScript )
        {
            mWriter.SeekBegin( mPositionBase + sectionHeader.FirstElementAddress );
            messageScript.ToStream( mWriter.BaseStream, true );
        }

        public void WriteStringSection( ref FlowScriptBinarySectionHeader sectionHeader, byte[] stringSection )
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
