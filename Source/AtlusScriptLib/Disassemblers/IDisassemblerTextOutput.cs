using System;

namespace AtlusScriptLib.Disassemblers
{
    public interface IDisassemblerTextOutput : IDisposable
    {
        void Put(string text);

        void PutNewline();

        void PutLine(string text);

        void PutCommentLine(string text);
    }
}
