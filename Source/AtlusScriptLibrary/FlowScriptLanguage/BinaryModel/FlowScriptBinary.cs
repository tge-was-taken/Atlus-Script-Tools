using System;
using System.Collections.ObjectModel;
using System.IO;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.FlowScriptLanguage.BinaryModel.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel;

namespace AtlusScriptLibrary.FlowScriptLanguage.BinaryModel
{
    // Todo: ensure immutability
    public sealed class FlowScriptBinary
    {
        public static FlowScriptBinary FromFile( string path )
        {
            return FromFile( path, BinaryFormatVersion.Unknown );
        }

        public static FlowScriptBinary FromFile( string path, BinaryFormatVersion version )
        {
            using ( var fileStream = File.OpenRead( path ) )
                return FromStream( fileStream, version );
        }

        public static FlowScriptBinary FromStream( Stream stream, bool leaveOpen = false )
        {
            return FromStream( stream, BinaryFormatVersion.Unknown, leaveOpen );
        }

        public static FlowScriptBinary FromStream( Stream stream, BinaryFormatVersion version, bool leaveOpen = false )
        {
            using ( var reader = new FlowScriptBinaryReader( stream, version, leaveOpen ) )
            {
                return reader.ReadBinary();
            }
        }

        // these fields are internal because they are used by the builder
        internal BinaryHeader mHeader;
        internal BinarySectionHeader[] mSectionHeaders;
        internal BinaryLabel[] mProcedureLabelSection;
        internal BinaryLabel[] mJumpLabelSection;
        internal BinaryInstruction[] mTextSection;
        internal MessageScriptBinary mMessageScriptSection;
        internal byte[] mStringSection;
        internal BinaryFormatVersion mFormatVersion;

        public BinaryHeader Header
        {
            get { return mHeader; }
        }

        public ReadOnlyCollection<BinarySectionHeader> SectionHeaders
        {
            get
            {
                if ( mSectionHeaders == null )
                    return null;
                return new ReadOnlyCollection<BinarySectionHeader>( mSectionHeaders );
            }
        }

        public ReadOnlyCollection<BinaryLabel> ProcedureLabelSection
        {
            get
            {
                if ( mProcedureLabelSection == null )
                    return null;
                return new ReadOnlyCollection<BinaryLabel>( mProcedureLabelSection );
            }
        }

        public ReadOnlyCollection<BinaryLabel> JumpLabelSection
        {
            get
            {
                if ( mJumpLabelSection == null )
                    return null;
                return new ReadOnlyCollection<BinaryLabel>( mJumpLabelSection );
            }
        }

        public ReadOnlyCollection<BinaryInstruction> TextSection
        {
            get
            {
                if ( mTextSection == null )
                    return null;
                return new ReadOnlyCollection<BinaryInstruction>( mTextSection );
            }
        }

        public MessageScriptBinary MessageScriptSection
        {
            get { return mMessageScriptSection; }
            set
            {
                // Fixup size
                int sizeDifference = value.Header.FileSize - mMessageScriptSection.Header.FileSize;

                if ( sizeDifference != 0 )
                {
                    var sectionHeaderIndex = Array.FindIndex( mSectionHeaders, x => x.SectionType == BinarySectionType.MessageScriptSection );

                    if ( sectionHeaderIndex != -1 )
                    {
                        mSectionHeaders[sectionHeaderIndex].ElementCount = mMessageScriptSection.Header.FileSize;

                        int lastHeaderIndex = mSectionHeaders.Length - 1;
                        if ( sectionHeaderIndex != lastHeaderIndex )
                        {
                            int numHeadersToFixUp = sectionHeaderIndex - lastHeaderIndex;
                            for ( int i = sectionHeaderIndex + 1; i < numHeadersToFixUp; i++ )
                            {
                                mSectionHeaders[i].FirstElementAddress += sizeDifference;
                            }
                        }
                    }
                    else
                    {
                        throw new NotImplementedException( "Adding a MessageScript section where it does not exist yet is not implemented" );
                    }
                }

                mMessageScriptSection = value;
            }
        }

        public ReadOnlyCollection<byte> StringSection
        {
            get
            {
                if ( mStringSection == null )
                    return null;
                return new ReadOnlyCollection<byte>( mStringSection );
            }
        }

        public BinaryFormatVersion FormatVersion
        {
            get { return mFormatVersion; }
        }

        // this constructor is internal because it is used by the builder
        internal FlowScriptBinary()
        {
        }

        public void ToFile( string path )
        {
            ToStream( FileUtils.Create( path ) );
        }

        public Stream ToStream()
        {
            var stream = new MemoryStream();
            ToStream( stream, true );
            return stream;
        }

        public void ToStream( Stream stream, bool leaveOpen = false )
        {
            using ( var writer = new FlowScriptBinaryWriter( stream, mFormatVersion, leaveOpen ) )
            {
                writer.WriteBinary( this );
            }
        }
    }
}
