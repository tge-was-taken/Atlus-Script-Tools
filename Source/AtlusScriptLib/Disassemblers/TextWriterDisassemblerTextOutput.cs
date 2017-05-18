using System.IO;

namespace AtlusScriptLib.Disassemblers
{
    public class TextWriterDisassemblerTextOutput : IDisassemblerTextOutput
    {
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
            TextWriter.Dispose();
        }
    }
}
