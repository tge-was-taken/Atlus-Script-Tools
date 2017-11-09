using System;
using System.Text;

namespace AtlusScriptLib.Common.Text.OutputProviders
{
    public sealed class StringBuilderTextOutputProvider : ITextOutputProvider
    {
        public StringBuilder StringBuilder { get; }

        public StringBuilderTextOutputProvider()
        {
            StringBuilder = new StringBuilder();
        }

        public StringBuilderTextOutputProvider( StringBuilder stringBuilder )
        {
            StringBuilder = stringBuilder ?? throw new ArgumentNullException( nameof( stringBuilder ) );
        }

        public void WriteLine()
        {
            StringBuilder.AppendLine();
        }

        public void WriteLine( string value )
        {
            StringBuilder.AppendLine( value );
        }

        public void WriteLine( object value )
        {
            StringBuilder.AppendLine( value.ToString() );
        }

        public void Write( char value )
        {
            StringBuilder.Append( value );
        }

        public void Write( string value )
        {
            StringBuilder.Append( value );
        }

        public void Write( object value )
        {
            StringBuilder.Append( value );
        }

        void IDisposable.Dispose()
        {
        }
    }
}
