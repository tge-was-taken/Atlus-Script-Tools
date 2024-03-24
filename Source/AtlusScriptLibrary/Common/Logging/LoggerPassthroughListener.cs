namespace AtlusScriptLibrary.Common.Logging;

public class LoggerPassthroughListener : LogListener
{
    private Logger mLogger;

    public LoggerPassthroughListener(Logger logger)
    {
        mLogger = logger;
    }

    protected override void OnLogCore(object sender, LogEventArgs e)
    {
        mLogger.Log(e.Level, e.Message);
    }
}
