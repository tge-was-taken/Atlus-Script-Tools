using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Logging
{
    public class Logger
    {
        public event LogEventHandler Log;

        public string Name { get; }

        public Logger( string name )
        {
            Name = name;
        }

        public void Debug( string message )
        {
            Log( this, new LogEventArgs( LogLevel.Debug, message ) );
        }

        public void Info( string message )
        {
            Log( this, new LogEventArgs( LogLevel.Info, message ) );
        }

        public void Warning( string message )
        {
            Log( this, new LogEventArgs( LogLevel.Warning, message ) );
        }

        public void Error( string message )
        {
            Log( this, new LogEventArgs( LogLevel.Error, message ) );
        }

        public void Fatal( string message )
        {
            Log( this, new LogEventArgs( LogLevel.Fatal, message ) );
        }
    }

    public delegate void LogEventHandler( object sender, LogEventArgs e );

    public enum LogLevel
    {
        Debug,
        Info,
        Warning,
        Error,
        Fatal
    }
}
