using System;
using AtlusScriptLib.FlowScriptLanguage.BinaryModel;

namespace AtlusScriptLib.FlowScriptLanguage.Decompiler
{
    public class FlowScriptDecompiler : IDisposable
    {
        private bool mDisposed = false;
        private string output;

        public FlowScriptDecompiler( string output )
        {
            this.output = output;
        }

        public void Decompile( FlowScriptBinary script )
        {

        }

        public void Dispose()
        {
            Dispose( true );
        }

        protected virtual void Dispose( bool disposing )
        {
            if ( mDisposed )
                return;

            mDisposed = true;
        }
    }
}
