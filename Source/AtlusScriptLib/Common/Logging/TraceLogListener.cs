using System;
using System.Diagnostics;

namespace AtlusScriptLib.Common.Logging
{
    public class TraceLogListener : LogListener
    {
        protected override void OnLog( object sender, LogEventArgs e )
        {
            Trace.WriteLine( $"{DateTime.Now} {e.ChannelName} {e.Level}: {e.Message}" );
        }
    }
}
