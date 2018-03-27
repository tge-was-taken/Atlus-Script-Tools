using System;
using System.IO;
using AtlusScriptLibrary.Common.IO;
using AtlusScriptLibrary.Common.Logging;

namespace AtlusScriptCompiler
{
    public class FileAndConsoleLogListener : ConsoleLogListener, IDisposable
    {
        private readonly StreamWriter mFileWriter;
        private readonly LogLevel mConsoleLogFilter;
        private bool mDisposed;

        public FileAndConsoleLogListener( bool useColors, LogLevel filter ) : base( useColors, LogLevel.All )
        {
            mFileWriter = FileUtils.CreateText( Program.AssemblyName.Name + ".log" );
            mConsoleLogFilter = filter;
        }

        public FileAndConsoleLogListener( string channelName, bool useColors ) : base( channelName, useColors )
        {
            mFileWriter = FileUtils.CreateText( Program.AssemblyName.Name + ".log" );
        }

        protected override void OnLogCore( object sender, LogEventArgs e )
        {
            mFileWriter.WriteLine( $"{DateTime.Now} {e.ChannelName} {e.Level}: {e.Message}" );

            if ( mConsoleLogFilter.HasFlag(e.Level) )
                base.OnLogCore( sender, e );
        }

        protected virtual void Dispose( bool disposing )
        {
            if ( !mDisposed && disposing )
            {
                mFileWriter.Dispose();
                mDisposed = true;
            }
        }

        ~FileAndConsoleLogListener()
        {
            Dispose( false );
        }

        public void Dispose()
        {
            Dispose( true );
            GC.SuppressFinalize(this);
        }
    }
}