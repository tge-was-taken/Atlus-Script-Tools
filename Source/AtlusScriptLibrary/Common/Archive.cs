using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using AtlusScriptLibrary.Common.IO;

namespace AtlusScriptLibrary.Common
{
    public enum ArchiveVersion
    {
        Unknown,

        /// <summary>
        /// 252 bytes filename, 4 bytes filesize
        /// </summary>
        Version1,

        /// <summary>
        /// Entry count header, 32 bytes filename, 4 bytes filesize
        /// </summary>
        Version2,

        /// <summary>
        /// Entry count header, 24 bytes filename, 4 bytes filesize
        /// </summary>
        Version3,

        Autodetect
    }

    public sealed class Archive : IDisposable, IEnumerable<string>
    {
        //
        // Static methods
        //
        public static bool IsValidArchive( string filepath )
        {
            using ( var stream = File.OpenRead( filepath ) )
                return IsValidArchive( stream );
        }

        public static bool IsValidArchive( byte[] data )
        {
            using ( var stream = new MemoryStream( data ) )
                return IsValidArchive( stream );
        }

        public static bool IsValidArchive( Stream stream )
        {
            return DetectVersion( stream ) != ArchiveVersion.Unknown;
        }

        public static bool TryOpenArchive( string filepath, out Archive archive )
        {
            using ( var stream = File.OpenRead( filepath ) )
                return TryOpenArchive( stream, out archive );
        }

        public static bool TryOpenArchive( Stream stream, out Archive archive )
        {
            var version = DetectVersion( stream );
            if ( version == ArchiveVersion.Unknown )
            {
                archive = null;
                return false;
            }

            archive = new Archive( stream, version );
            return true;
        }

        private static bool IsValidArchiveVersion1( Stream stream )
        {
            // check if the file is too small to be a proper pak file
            if ( stream.Length <= 256 )
            {
                return false;
            }

            // read some test data
            byte[] testData = new byte[256];
            stream.Read( testData, 0, 256 );
            stream.Position = 0;

            // check if first byte is zero, if so then no name can be stored thus making the file corrupt
            if ( testData[0] == 0x00 )
                return false;

            bool nameTerminated = false;
            for ( int i = 0; i < 252; i++ )
            {
                if ( testData[i] == 0x00 )
                    nameTerminated = true;

                // If the name has already been terminated but there's still data in the reserved space,
                // fail the test
                if ( nameTerminated && testData[i] != 0x00 )
                    return false;
            }

            int testLength = BitConverter.ToInt32( testData, 252 );

            // sanity check, if the length of the first file is >= 100 mb, fail the test
            if ( testLength >= stream.Length || testLength < 0 )
            {
                return false;
            }

            return true;
        }

        private static bool IsValidArchiveVersion2And3( Stream stream, int entrySize )
        {
            // check stream length
            if ( stream.Length <= 4 + entrySize )
                return false;

            byte[] testData = new byte[4 + entrySize];
            stream.Read( testData, 0, 4 + entrySize );
            stream.Position = 0;

            int numOfFiles = BitConverter.ToInt32( testData, 0 );

            // num of files sanity check
            if ( numOfFiles > 1024 || numOfFiles < 1 || ( numOfFiles * entrySize ) > stream.Length )
            {
                numOfFiles = EndiannessHelper.Swap( numOfFiles );

                if ( numOfFiles > 1024 || numOfFiles < 1 || ( numOfFiles * entrySize ) > stream.Length )
                    return false;
            }

            // check if the name field is correct
            bool nameTerminated = false;
            for ( int i = 0; i < entrySize - 4; i++ )
            {
                if ( testData[4 + i] == 0x00 )
                {
                    if ( i == 0 )
                        return false;

                    nameTerminated = true;
                }

                if ( testData[4 + i] != 0x00 && nameTerminated )
                    return false;
            }

            // first entry length sanity check
            int length = BitConverter.ToInt32( testData, entrySize );
            if ( length >= stream.Length || length < 0 )
            {
                length = EndiannessHelper.Swap( length );

                if ( length >= stream.Length || length < 0 )
                    return false;
            }

            return true;
        }

        private static ArchiveVersion DetectVersion( Stream stream )
        {
            if ( IsValidArchiveVersion1( stream ) )
                return ArchiveVersion.Version1;

            if ( IsValidArchiveVersion2And3( stream, 36 ) )
                return ArchiveVersion.Version2;

            if ( IsValidArchiveVersion2And3( stream, 28 ) )
                return ArchiveVersion.Version3;

            return ArchiveVersion.Unknown;
        }

        //
        // Properties
        //
        protected long StreamStartPosition { get; private set; }

        protected Stream Stream { get; private set; }

        protected bool OwnsStream { get; private set; }

        protected Dictionary<string, ArchiveEntry> EntryMap { get; private set; }

        public ArchiveVersion Version { get; set; }
        
        //
        // Ctors
        //
        public Archive( string filepath, ArchiveVersion version = ArchiveVersion.Autodetect )
        {
            Initialize( File.OpenRead( filepath ), true, version );
        }

        public Archive( Stream stream, ArchiveVersion version = ArchiveVersion.Autodetect, bool ownsStream = true )
        {
            Initialize( stream, ownsStream, version );
        }

        public Archive( byte[] data, ArchiveVersion version = ArchiveVersion.Autodetect )
        {
            Initialize( new MemoryStream( data ), true, version );
        }

        //
        // Public Methods
        //
        public StreamView this[string fileName] => OpenFile( fileName );

        public IEnumerable<string> EnumerateFiles() => EntryMap.Select( x => x.Key );

        public bool TryOpenFile( string filename, out StreamView stream )
        {
            if ( !EntryMap.TryGetValue( filename, out var entry ) )
            {
                stream = null;
                return false;
            }

            stream = new StreamView( Stream, entry.DataPosition, entry.Length );
            return true;
        }

        public StreamView OpenFile( string filename )
        {
            if ( !TryOpenFile( filename, out var stream ) )
            {
                throw new Exception( "File does not exist" );
            }

            return stream;
        }

        public void Dispose()
        {
            Stream.Dispose();
        }

        public void Save( string filePath )
        {
            using ( var fileStream = FileUtils.Create( filePath ) )
            {
                Stream.Position = 0;
                Stream.CopyTo( fileStream );
            }
        }

        public void Save( Stream stream )
        {
            Stream.Position = 0;
            Stream.CopyTo( stream );
        }

        public IEnumerator<string> GetEnumerator()
        {
            return EnumerateFiles().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private void Initialize( Stream stream, bool ownsStream, ArchiveVersion version )
        {
            StreamStartPosition = stream.Position;
            Stream = stream;
            OwnsStream = ownsStream;
            EntryMap = new Dictionary<string, ArchiveEntry>();

            if ( version == ArchiveVersion.Autodetect )
                Version = DetectVersion( Stream );
            else
                Version = version;

            var reader = new ArchiveReader( stream, Version, true );
            foreach ( var entry in reader.ReadEntries( true ) )
            {
                EntryMap[entry.FileName] = entry;
            }
        }
    }

    public struct ArchiveEntry
    {
        public string FileName;
        public int Length;
        public long DataPosition;
    }

    internal class ArchiveReader : IDisposable
    {
        protected EndianBinaryReader Reader { get; }

        protected StringBuilder StringBuilder { get; }

        protected ArchiveVersion Version { get; }

        public ArchiveReader( Stream stream, ArchiveVersion version, bool leaveOpen = false )
        {
            Reader = new EndianBinaryReader( stream, Encoding.ASCII, leaveOpen, Endianness.LittleEndian );
            StringBuilder = new StringBuilder();
            Version = version;
        }

        public IEnumerable<ArchiveEntry> ReadEntries( bool skipData )
        {
            while ( true )
            {
                if ( Version == ArchiveVersion.Version1 )
                {
                    long entryStartPosition = Reader.Position;
                    if ( entryStartPosition == Reader.BaseStreamLength )
                    {
                        yield break;
                    }

                    // read entry name
                    while ( true )
                    {
                        byte b = Reader.ReadByte();
                        if ( b == 0 )
                            break;

                        StringBuilder.Append( ( char )b );

                        // just to be safe
                        if ( StringBuilder.Length == 252 )
                            break;
                    }

                    string fileName = StringBuilder.ToString();

                    // set position to length field
                    Reader.Position = entryStartPosition + 252;

                    // read entry length
                    int length = Reader.ReadInt32();

                    if ( fileName.Length == 0 || length <= 0 || length > 1024 * 1024 * 100 )
                    {
                        yield break;
                    }

                    // make an entry
                    ArchiveEntry entry;
                    entry.FileName = fileName;
                    entry.Length = length;
                    entry.DataPosition = Reader.Position;

                    // clear string builder for next iteration
                    StringBuilder.Clear();

                    if ( skipData )
                    {
                        Reader.Position = AlignmentHelper.Align( Reader.Position + entry.Length, 64 );
                    }

                    yield return entry;
                }
                else if ( Version == ArchiveVersion.Version2 || Version == ArchiveVersion.Version3 )
                {
                    int entryCount = Reader.ReadInt32();
                    int nameLength = 32;
                    if ( Version == ArchiveVersion.Version3 )
                        nameLength = 24;

                    for ( int i = 0; i < entryCount; i++ )
                    {
                        long entryStartPosition = Reader.Position;
                        if ( entryStartPosition == Reader.BaseStreamLength )
                        {
                            break;
                        }

                        // read entry name
                        for ( int j = 0; j < nameLength; j++ )
                        {
                            byte b = Reader.ReadByte();

                            if ( b != 0 )
                                StringBuilder.Append( ( char )b );
                        }

                        string fileName = StringBuilder.ToString();

                        // read entry length
                        int length = Reader.ReadInt32();

                        if ( fileName.Length == 0 || length <= 0 || length > 1024 * 1024 * 100 )
                        {
                            break;
                        }

                        // make an entry
                        ArchiveEntry entry;
                        entry.FileName = fileName;
                        entry.Length = length;
                        entry.DataPosition = Reader.Position;

                        // clear string builder for next iteration
                        StringBuilder.Clear();

                        if ( skipData )
                        {
                            Reader.Position += entry.Length;
                        }

                        yield return entry;
                    }

                    yield break;
                }
            }
        }

        public void Dispose()
        {
            ( ( IDisposable )Reader ).Dispose();
        }
    }
}
