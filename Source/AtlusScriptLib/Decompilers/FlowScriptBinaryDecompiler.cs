using System;

namespace AtlusScriptLib.Decompilers
{
    public class FlowScriptBinaryDecompiler : IDisposable
    {
        private bool mDisposed = false;


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
