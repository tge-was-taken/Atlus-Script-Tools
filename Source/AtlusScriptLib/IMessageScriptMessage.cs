using System.Collections.Generic;

namespace AtlusScriptLib
{
    public interface IMessageScriptMessage
    {
        MessageScriptMessageType Type { get; }

        string Identifier { get; }

        List<MessageScriptLine> Lines { get; }
    }
}