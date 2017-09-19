using System;

namespace AtlusScriptLib.Common.Logging
{
    public abstract class LogListener
    {
        public string Name { get; }

        public LogListener( string channelName )
        {
            Name = channelName;
        }

        public void Subscribe( Logger logger )
        {
            logger.Log += OnLog;
        }

        public void Unsubscribe( Logger logger )
        {
            logger.Log -= OnLog;
        }

        protected abstract void OnLog( object sender, LogEventArgs e );
    }

    public class ConsoleLogListener : LogListener
    {
        public bool UseColors { get; }

        public ConsoleLogListener( string channelName, bool useColors ) : base( channelName )
        {
            UseColors = useColors;
        }

        protected override void OnLog( object sender, LogEventArgs e )
        {
            if ( UseColors )
                Console.ForegroundColor = GetConsoleColorForSeverityLevel( e.Level );

            Console.WriteLine($"{DateTime.Now} {e.Level}: {e.Message}");
        }

        private ConsoleColor GetConsoleColorForSeverityLevel( LogLevel level )
        {
            switch ( level )
            {
                case LogLevel.Debug:
                    return ConsoleColor.White;
                case LogLevel.Info:
                    return ConsoleColor.Green;
                case LogLevel.Warning:
                    return ConsoleColor.Yellow;
                case LogLevel.Error:
                    return ConsoleColor.Red;
                case LogLevel.Fatal:
                    return ConsoleColor.DarkRed;
                default:
                    return ConsoleColor.White;
            }
        }
    }
}
