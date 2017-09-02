using System;
using System.IO;

namespace AtlusScriptLib.Text.OutputProviders
{
    public class StreamWriterTextOutputProvider : ITextOutputProvider
    {
        public StreamWriter Writer { get; }

        public StreamWriterTextOutputProvider( StreamWriter writer )
        {
            Writer = writer ?? throw new ArgumentNullException( nameof( writer ) );
        }

        public void Write( char value )
        {
            Writer.Write( value );
        }

        public void Write( string value )
        {
            Writer.Write( value );
        }

        public void Write( object value )
        {
            Writer.Write( value );
        }

        public void WriteLine()
        {
            Writer.WriteLine();
        }

        public void WriteLine( string value )
        {
            Writer.WriteLine( value );
        }

        public void WriteLine( object value )
        {
            Writer.WriteLine( value );
        }

        public void Dispose()
        {
            Writer.Dispose();
        }
    }
}
