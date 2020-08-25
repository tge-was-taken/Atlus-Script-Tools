using System;
using System.Text;

namespace AtlusScriptLibrary.Common.Logging
{
    public class ConsoleLogListener : LogListener
    {
        public bool UseColors { get; set; }

        public ConsoleLogListener( bool useColors, LogLevel filter ) : base( filter )
        {
            UseColors = useColors;
            TrySetConsoleEncoding();
        }

        public ConsoleLogListener( string channelName, bool useColors ) : base( channelName )
        {
            UseColors = useColors;
            TrySetConsoleEncoding();
        }

        private static void TrySetConsoleEncoding()
        {
            try
            {
                Console.OutputEncoding = Encoding.Unicode;
            }
            catch (Exception)
            {
            }
        }

        protected override void OnLogCore( object sender, LogEventArgs e )
        {
            ConsoleColor prevColor = 0;

            if ( UseColors )
            {
                prevColor = Console.ForegroundColor;
                Console.ForegroundColor = GetConsoleColorForSeverityLevel( e.Level );
            }

            Console.WriteLine($"{DateTime.Now} {e.ChannelName} {e.Level}: {e.Message}");

            if ( UseColors )
            {
                Console.ForegroundColor = prevColor;
            }
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
