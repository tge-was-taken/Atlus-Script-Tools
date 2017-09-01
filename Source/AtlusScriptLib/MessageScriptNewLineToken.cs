using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib
{
    public class MessageScriptNewLineToken : IMessageScriptLineToken
    {
        public const byte Value = 0x0A;

        public MessageScriptTokenType Type => MessageScriptTokenType.NewLine;

        public override string ToString()
        {
            return "<new line>";
        }
    }
}
