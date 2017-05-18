using System;

namespace AtlusScriptLib.Decompilers
{
    public class FlowScriptBinaryDecompiler : IDisposable
    {
        private bool mDisposed = false;
        private string output;

        public FlowScriptBinaryDecompiler(string output)
        {
            this.output = output;
        }

        public void Decompile(FlowScriptBinary script)
        {

        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (mDisposed)
                return;

            mDisposed = true;
        }
    }
}
