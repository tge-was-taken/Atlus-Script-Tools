using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.Common.Logging
{
    public class Logger
    {
        public event LogEventHandler LogEvent;

        public string Name { get; }

        public Logger( string name )
        {
            Name = name;
        }

        public void Log( LogLevel level, string message )
        {
            LogEvent( this, new LogEventArgs( Name, level, message ) );
        }

        public void Debug( string message )
        {
            Log( LogLevel.Debug, message );
        }

        public void Info( string message )
        {
            Log( LogLevel.Info, message );
        }

        public void Warning( string message )
        {
            Log( LogLevel.Warning, message );
        }

        public void Error( string message )
        {
            Log( LogLevel.Error, message );
        }

        public void Fatal( string message )
        {
            Log( LogLevel.Fatal, message );
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
