using System.Text;

namespace AtlusScriptLib.Disassemblers
{
    public class StringBuilderDisassemblerTextOutput : IDisassemblerTextOutput
    {
        public StringBuilder StringBuilder { get; }

        public StringBuilderDisassemblerTextOutput(StringBuilder stringBuilder)
        {
            StringBuilder = stringBuilder;
        }

        public void Put(string text)
        {
            StringBuilder.Append(text);
        }

        public void PutCommentLine(string text)
        {
            StringBuilder.AppendLine("# " + text);
        }

        public void PutLine(string text)
        {
            StringBuilder.AppendLine(text);
        }

        public void PutNewline()
        {
            StringBuilder.AppendLine();
        }

        public void Dispose()
        {
        }
    }

}
