namespace AtlusScriptLib.Common.Logging
{
    public class LoggerPassthroughListener : LogListener
    {
        private Logger mLogger;

        public LoggerPassthroughListener( Logger logger )
        {
            mLogger = logger;
        }

        protected override void OnLog( object sender, LogEventArgs e )
        {
            mLogger.Log( e.Level, e.Message );
        }
    }
}
