using System;
using System.IO;
using AtlusScriptLib.Common.Logging;

namespace AtlusScriptCompiler
{
    public class FileAndConsoleLogListener : ConsoleLogListener
    {
        private readonly StreamWriter mFileWriter;

        public FileAndConsoleLogListener( bool useColors, LogLevel filter ) : base( useColors, filter )
        {
            mFileWriter = File.CreateText( Program.AssemblyName.Name + ".log" );
        }

        public FileAndConsoleLogListener( string channelName, bool useColors ) : base( channelName, useColors )
        {
            mFileWriter = File.CreateText( Program.AssemblyName.Name + ".log" );
        }

        protected override void OnLogCore( object sender, LogEventArgs e )
        {
            mFileWriter.WriteLine( $"{DateTime.Now} {e.ChannelName} {e.Level}: {e.Message}" );

            base.OnLogCore( sender, e );
        }
    }
}