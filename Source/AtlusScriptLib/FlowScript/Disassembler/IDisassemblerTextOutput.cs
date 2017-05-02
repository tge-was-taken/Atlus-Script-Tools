using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib.FlowScript.Disassembler
{
    public interface IDisassemblerTextOutput : IDisposable
    {
        void Put(string text);

        void PutNewline();

        void PutLine(string text);

        void PutCommentLine(string text);
    }
}
