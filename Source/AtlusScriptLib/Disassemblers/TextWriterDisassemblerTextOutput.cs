using System.IO;

namespace AtlusScriptLib.Disassemblers
{
    public class TextWriterDisassemblerTextOutput : IDisassemblerTextOutput
    {
        private bool mDisposed;

        public TextWriter TextWriter { get; }

        public TextWriterDisassemblerTextOutput(TextWriter textWriter)
        {
            TextWriter = textWriter;
        }

        public void Put(string text)
        {
            TextWriter.Write(text);
        }

        public void PutCommentLine(string text)
        {
            TextWriter.WriteLine("# " + text);
        }

        public void PutLine(string text)
        {
            TextWriter.WriteLine(text);
        }

        public void PutNewline()
        {
            TextWriter.WriteLine();
        }

        public void Dispose()
        {
            Dispose(true);   
        }

        protected virtual void Dispose(bool disposing)
        {
            if (mDisposed)
                return;

            TextWriter.Dispose();
            mDisposed = true;
        }
    }
}
