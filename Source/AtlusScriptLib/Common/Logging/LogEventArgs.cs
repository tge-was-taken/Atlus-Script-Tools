using System;

namespace AtlusScriptLib.Common.Logging
{
    public class LogEventArgs : EventArgs
    {
        public LogLevel Level { get; }

        public string Message { get; }

        public LogEventArgs( LogLevel level, string message )
        {
            Level = level;
            Message = message;
        }
    }
}
