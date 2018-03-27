using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLibrary.Common.Logging
{
    public static class LoggerManager
    {
        private static List<Logger> sLoggers = new List<Logger>();
        private static List<LogListener> sListeners = new List<LogListener>();

        public static void RegisterLogger( Logger logger )
        {
            sLoggers.Add( logger );
        }

        public static void UnregisterLogger( Logger logger )
        {
            sLoggers.Remove( logger );
        }

        public static void RegisterListener( LogListener listener )
        {
            foreach ( var item in sLoggers.Where( x => x.Name == listener.ChannelName ) )
            {
                listener.Subscribe( item );
            }

            sListeners.Add( listener );
        }

        public static void UnregisterListener( LogListener listener )
        {
            foreach ( var item in sLoggers.Where( x => x.Name == listener.ChannelName ) )
            {
                listener.Unsubscribe( item );
            }

            sListeners.Remove( listener );
        }
    }
}
