using System;
using System.Diagnostics;

namespace AtlusScriptLibrary.Common.Logging
{
    public class TraceLogListener : LogListener
    {
        protected override void OnLogCore( object sender, LogEventArgs e )
        {
            Trace.WriteLine( $"{DateTime.Now} {e.ChannelName} {e.Level}: {e.Message}" );
        }
    }

    public class DebugLogListener : LogListener
    {
        protected override void OnLogCore( object sender, LogEventArgs e )
        {
            Debug.WriteLine( $"{DateTime.Now} {e.ChannelName} {e.Level}: {e.Message}" );
        }
    }
}
