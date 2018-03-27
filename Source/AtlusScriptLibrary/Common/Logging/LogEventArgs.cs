using System;

namespace AtlusScriptLibrary.Common.Logging
{
    public class LogEventArgs : EventArgs
    {
        public string ChannelName { get; }

        public LogLevel Level { get; }

        public string Message { get; }

        public LogEventArgs( string channelName, LogLevel level, string message )
        {
            Level = level;
            Message = message;
        }
    }
}
