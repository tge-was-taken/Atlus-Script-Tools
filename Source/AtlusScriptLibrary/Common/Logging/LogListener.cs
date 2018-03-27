namespace AtlusScriptLibrary.Common.Logging
{
    public abstract class LogListener
    {
        public string ChannelName { get; }

        public LogLevel Filter { get; set; } = LogLevel.All;

        public LogListener()
        {

        }

        public LogListener( LogLevel filter )
        {
            Filter = filter;
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

        protected void OnLog( object sender, LogEventArgs e )
        {
            if ( Filter.HasFlag( e.Level ) )
                OnLogCore( sender, e );
        }

        protected abstract void OnLogCore( object sender, LogEventArgs e );
    }
}
