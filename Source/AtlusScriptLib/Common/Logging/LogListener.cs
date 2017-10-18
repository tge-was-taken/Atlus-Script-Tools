using System;

namespace AtlusScriptLib.Common.Logging
{
    public abstract class LogListener
    {
        public string ChannelName { get; }

        public LogListener()
        {

        }

        public LogListener( string channelName )
        {
            ChannelName = channelName;
        }

        public void Subscribe( Logger logger )
        {
            logger.LogEvent += OnLog;
        }

        public void Unsubscribe( Logger logger )
        {
            logger.LogEvent -= OnLog;
        }

        protected abstract void OnLog( object sender, LogEventArgs e );
    }
}
