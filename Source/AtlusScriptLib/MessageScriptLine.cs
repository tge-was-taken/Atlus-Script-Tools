using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlusScriptLib
{
    public class MessageScriptLine
    {
        public List<IMessageScriptLineToken> Tokens { get; }

        public MessageScriptLine()
        {
            Tokens = new List<IMessageScriptLineToken>();
        }

        public MessageScriptLine(List<IMessageScriptLineToken> tokens)
        {
            Tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
        }

        public MessageScriptLine(params IMessageScriptLineToken[] tokens)
        {
            Tokens = tokens.ToList();
        }
    }
}
