using System;
using System.IO;
using System.Text;

namespace AtlusScriptLibrary.Common.Text
{
    public sealed class FileTextWriter : TextWriter
    {
        private readonly StreamWriter mWriter;

        public string Path { get; }

        public override Encoding Encoding => mWriter.Encoding;

        public FileTextWriter( string path )
        {
            Path = path ?? throw new ArgumentNullException( nameof( path ) );
            mWriter = new StreamWriter( path );
        }

        public override void Write( char value )
        {
            mWriter.Write( value );
        }

        protected override void Dispose( bool disposing )
        {
            if ( disposing )
            {
                mWriter.Dispose();
            }
        }
    }
}
