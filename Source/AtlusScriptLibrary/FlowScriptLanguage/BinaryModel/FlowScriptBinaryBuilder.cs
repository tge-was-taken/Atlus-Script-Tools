using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AtlusScriptLibrary.Common.Text.Encodings;
using AtlusScriptLibrary.MessageScriptLanguage;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

namespace AtlusScriptLibrary.FlowScriptLanguage.BinaryModel
{
    public sealed class FlowScriptBinaryBuilder
    {
        // required
        private readonly BinaryFormatVersion mFormatVersion;

        // optional
        private short mUserId;
        private IList<BinaryLabel> mProcedureLabelSection;
        private IList<BinaryLabel> mJumpLabelSection;
        private IList<BinaryInstruction> mTextSection;
        private MessageScriptBinary mMessageScriptSection;
        private IList<byte> mStringSection;

        public FlowScriptBinaryBuilder( BinaryFormatVersion version )
        {
            if ( !Enum.IsDefined( typeof( BinaryFormatVersion ), version ) )
                throw new ArgumentOutOfRangeException( nameof( version ),
                    $"Value should be defined in the {nameof( BinaryFormatVersion )} enum." );

            mFormatVersion = version;
        }

        public void SetUserId( short value )
        {
            mUserId = value;
        }

        public void SetProcedureLabelSection( IList<BinaryLabel> procedureLabelSection )
        {
            mProcedureLabelSection = procedureLabelSection ?? throw new ArgumentNullException( nameof( procedureLabelSection ) );
        }

        public void AddProcedureLabel( BinaryLabel label )
        {
            if ( mProcedureLabelSection == null )
                mProcedureLabelSection = new List<BinaryLabel>();

            mProcedureLabelSection.Add( label );
        }

        public void SetJumpLabelSection( IList<BinaryLabel> jumpLabelSection )
        {
            mJumpLabelSection = jumpLabelSection ?? throw new ArgumentNullException( nameof( jumpLabelSection ) );
        }

        public void AddJumpLabel( BinaryLabel label )
        {
            if ( mJumpLabelSection == null )
                mJumpLabelSection = new List<BinaryLabel>();

            mJumpLabelSection.Add( label );
        }

        public void SetTextSection( IList<BinaryInstruction> textSection )
        {
            mTextSection = textSection ?? throw new ArgumentNullException( nameof( textSection ) );
        }

        public void AddInstruction( BinaryInstruction instruction )
        {
            if ( mTextSection == null )
                mTextSection = new List<BinaryInstruction>();

            mTextSection.Add( instruction );
        }

        public void SetMessageScriptSection( MessageScriptBinary messageScriptSection )
        {
            mMessageScriptSection = messageScriptSection ?? throw new ArgumentNullException( nameof( messageScriptSection ) );
        }

        public void SetMessageScriptSection( MessageScript messageScriptSection )
        {
            mMessageScriptSection = messageScriptSection.ToBinary() ?? throw new ArgumentNullException( nameof( messageScriptSection ) );
        }

        public void SetStringSection( IList<byte> stringSection )
        {
            mStringSection = stringSection ?? throw new ArgumentNullException( nameof( stringSection ) );
        }

        public void AddString( string value, out int index )
        {
            if ( value == null )
                throw new ArgumentNullException( nameof( value ) );

            if ( mStringSection == null )
                mStringSection = new List<byte>();

            index = mStringSection.Count;

            var bytes = ShiftJISEncoding.Instance.GetBytes( value );

            foreach ( byte b in bytes )
                mStringSection.Add( b );

            mStringSection.Add( 0 );
        }

        public FlowScriptBinary Build()
        {
            // Pad out this section first before building the string section header
            if ( mStringSection != null )
            {
                while ( ( mStringSection.Count % 16 ) != 0 )
                    mStringSection.Add( 0 );
            }

            var binary = new FlowScriptBinary
            {
                mHeader = BuildHeader(),
                mSectionHeaders = BuildSectionHeaders(),
                mFormatVersion = mFormatVersion
            };

            // Copy the section data to the binary
            if ( mProcedureLabelSection != null )
                binary.mProcedureLabelSection = mProcedureLabelSection.ToArray();

            if ( mJumpLabelSection != null )
                binary.mJumpLabelSection = mJumpLabelSection.ToArray();

            if ( mTextSection != null )
                binary.mTextSection = mTextSection.ToArray();

            if ( mMessageScriptSection != null )
                binary.mMessageScriptSection = mMessageScriptSection;

            if ( mStringSection != null )
            {
                binary.mStringSection = mStringSection.ToArray();             
            }

            return binary;
        }

        private BinaryHeader BuildHeader()
        {
            return new BinaryHeader
            {
                FileType = BinaryHeader.FILE_TYPE,
                Compressed = false,
                UserId = mUserId,
                FileSize = CalculateFileSize(),
                Magic = BinaryHeader.MAGIC,
                Field0C = 0,
                SectionCount = CalculateSectionCount(),
                LocalIntVariableCount = CalculateLocalIntVariableCount(),
                LocalFloatVariableCount = CalculateLocalFloatVariableCount(),
                Endianness = 0,
                Field1A = 0,
                Padding = 0
            };
        }

        private BinarySectionHeader[] BuildSectionHeaders()
        {
            var sectionHeaders = new BinarySectionHeader[CalculateSectionCount()];

            int nextFirstElementAddress = BinaryHeader.SIZE + ( sectionHeaders.Length * BinarySectionHeader.SIZE );
            int currentSectionHeaderIndex = 0;
            BinarySectionHeader sectionHeader;

            if ( mProcedureLabelSection != null )
            {
                sectionHeader = BuildSectionHeader( BinarySectionType.ProcedureLabelSection, CalculateLabelSize(), mProcedureLabelSection.Count, nextFirstElementAddress );
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
                nextFirstElementAddress += ( sectionHeader.ElementCount * sectionHeader.ElementSize );
            }

            if ( mJumpLabelSection != null )
            {
                sectionHeader = BuildSectionHeader( BinarySectionType.JumpLabelSection, CalculateLabelSize(), mJumpLabelSection.Count, nextFirstElementAddress );
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
                nextFirstElementAddress += ( sectionHeader.ElementCount * sectionHeader.ElementSize );
            }

            if ( mTextSection != null )
            {
                sectionHeader = BuildSectionHeader( BinarySectionType.TextSection, BinaryInstruction.SIZE, mTextSection.Count, nextFirstElementAddress );
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
                nextFirstElementAddress += ( sectionHeader.ElementCount * sectionHeader.ElementSize );
            }

            if ( mMessageScriptSection != null )
            {
                sectionHeader = BuildSectionHeader( BinarySectionType.MessageScriptSection, sizeof( byte ), mMessageScriptSection.Header.FileSize, nextFirstElementAddress );
                sectionHeaders[currentSectionHeaderIndex++] = sectionHeader;
                nextFirstElementAddress += ( sectionHeader.ElementCount * sectionHeader.ElementSize );
            }

            if ( mStringSection != null )
            {
                sectionHeader = BuildSectionHeader( BinarySectionType.StringSection, sizeof( byte ), mStringSection.Count, nextFirstElementAddress );
                sectionHeaders[currentSectionHeaderIndex] = sectionHeader;
            }

            return sectionHeaders;
        }

        private BinarySectionHeader BuildSectionHeader( BinarySectionType type, int size, int count, int address )
        {
            return new BinarySectionHeader
            {
                SectionType = type,
                ElementSize = size,
                ElementCount = count,
                FirstElementAddress = address
            };
        }

        private int CalculateLabelSize()
        {
            return mFormatVersion.HasFlag( BinaryFormatVersion.Version1 ) ? BinaryLabel.SIZE_V1 :
                   mFormatVersion.HasFlag( BinaryFormatVersion.Version2 ) ? BinaryLabel.SIZE_V2 :
                   mFormatVersion.HasFlag( BinaryFormatVersion.Version3 ) ? BinaryLabel.SIZE_V3 :
                   throw new Exception( "Invalid format version" );
        }

        private int CalculateFileSize()
        {
            int size = BinaryHeader.SIZE;
            int labelSize = CalculateLabelSize();

            if ( mProcedureLabelSection != null )
                size += ( BinarySectionHeader.SIZE + ( mProcedureLabelSection.Count * labelSize ) );

            if ( mJumpLabelSection != null )
                size += ( BinarySectionHeader.SIZE + ( mJumpLabelSection.Count * labelSize ) );

            if ( mTextSection != null )
                size += ( BinarySectionHeader.SIZE + ( mTextSection.Count * BinaryInstruction.SIZE ) );

            if ( mMessageScriptSection != null )
                size += ( BinarySectionHeader.SIZE + ( mMessageScriptSection.Header.FileSize * sizeof( byte ) ) );

            if ( mStringSection != null )
                size += ( BinarySectionHeader.SIZE + ( mStringSection.Count * sizeof( byte ) ) );

            return size;
        }

        private int CalculateSectionCount()
        {
            int sectionCount = 0;
            if ( mProcedureLabelSection != null )
                sectionCount++;

            if ( mJumpLabelSection != null )
                sectionCount++;

            if ( mTextSection != null )
                sectionCount++;

            if ( mMessageScriptSection != null )
                sectionCount++;

            if ( mStringSection != null )
                sectionCount++;

            return sectionCount;
        }

        private short CalculateLocalIntVariableCount()
        {
            if ( mTextSection == null )
                return 0;

            int highestIndex = -1;
            for ( int i = 0; i < mTextSection.Count; i++ )
            {
                var instruction = mTextSection[i];

                if ( instruction.Opcode == Opcode.POPLIX || instruction.Opcode == Opcode.PUSHLIX )
                {
                    // check if it's a false positive
                    if ( i - 1 != -1 && ( mTextSection[i - 1].Opcode == Opcode.PUSHI || mTextSection[i - 1].Opcode == Opcode.PUSHF ) )
                    {
                        continue;
                    }

                    if ( instruction.OperandShort > highestIndex )
                        highestIndex = instruction.OperandShort;
                }
            }

            return ( short )( highestIndex + 1 );
        }

        private short CalculateLocalFloatVariableCount()
        {
            if ( mTextSection == null )
                return 0;

            int highestIndex = -1;
            for ( int i = 0; i < mTextSection.Count; i++ )
            {
                var instruction = mTextSection[i];

                if ( instruction.Opcode == Opcode.POPLFX || instruction.Opcode == Opcode.PUSHLFX )
                {
                    // check if it's a false positive
                    if ( i - 1 != -1 && ( mTextSection[i - 1].Opcode == Opcode.PUSHI || mTextSection[i - 1].Opcode == Opcode.PUSHF ) )
                    {
                        continue;
                    }

                    if ( instruction.OperandShort > highestIndex )
                        highestIndex = instruction.OperandShort;
                }
            }

            return ( short )( highestIndex + 1 );
        }
    }
}
