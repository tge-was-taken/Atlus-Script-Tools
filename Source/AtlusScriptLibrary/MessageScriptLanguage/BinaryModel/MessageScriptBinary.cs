using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.MessageScriptLanguage.BinaryModel.IO;

namespace AtlusScriptLibrary.MessageScriptLanguage.BinaryModel
{
    public class MessageScriptBinary
    {
        public static MessageScriptBinary FromFile( string path )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            return FromFile( path, BinaryFormatVersion.Unknown );
        }

        public static MessageScriptBinary FromFile( string path, BinaryFormatVersion version )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            if ( !Enum.IsDefined( typeof( BinaryFormatVersion ), version ) )
                throw new InvalidEnumArgumentException( nameof( version ), ( int )version,
                    typeof( BinaryFormatVersion ) );

            using ( var fileStream = File.OpenRead( path ) )
                return FromStream( fileStream, version );
        }

        public static MessageScriptBinary FromStream( Stream stream, bool leaveOpen = false )
        {
            if ( stream == null )
                throw new ArgumentNullException( nameof( stream ) );

            return FromStream( stream, BinaryFormatVersion.Unknown, leaveOpen );
        }

        public static MessageScriptBinary FromStream( Stream stream, BinaryFormatVersion version, bool leaveOpen = false )
        {
            if ( stream == null )
                throw new ArgumentNullException( nameof( stream ) );

            if ( !Enum.IsDefined( typeof( BinaryFormatVersion ), version ) )
                throw new InvalidEnumArgumentException( nameof( version ), ( int )version,
                    typeof( BinaryFormatVersion ) );

            using ( var reader = new MessageScriptBinaryReader( stream, version, leaveOpen ) )
            {
                return reader.ReadBinary();
            }
        }

        // these fields are internal because they are used by the builder, reader & writer
        internal BinaryHeader mHeader;
        internal BinaryDialogHeader[] mDialogHeaders;
        internal BinarySpeakerTableHeader mSpeakerTableHeader;
        internal BinaryFormatVersion mFormatVersion;

        public BinaryHeader Header => mHeader;

        public ReadOnlyCollection<BinaryDialogHeader> DialogHeaders
            => new ReadOnlyCollection<BinaryDialogHeader>( mDialogHeaders );

        public BinarySpeakerTableHeader SpeakerTableHeader => mSpeakerTableHeader;

        public BinaryFormatVersion FormatVersion => mFormatVersion;

        // this constructor is internal because it is used by the builder, reader & writer
        internal MessageScriptBinary()
        {
        }

        public void ToFile( string path )
        {
            if ( path == null )
                throw new ArgumentNullException( nameof( path ) );

            if ( string.IsNullOrEmpty( path ) )
                throw new ArgumentException( "Value cannot be null or empty.", nameof( path ) );

            using ( var stream = FileUtils.Create( path ) )
                ToStream( stream );
        }

        public Stream ToStream()
        {
            var stream = new MemoryStream();
            ToStream( stream, true );
            return stream;
        }

        public void ToStream( Stream stream, bool leaveOpen = false )
        {
            using ( var writer = new MessageScriptBinaryWriter( stream, mFormatVersion, leaveOpen ) )
            {
                writer.WriteBinary( this );
            }
        }
    }
}
