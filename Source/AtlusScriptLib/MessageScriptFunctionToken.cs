using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    public struct MessageScriptFunctionToken : IMessageScriptLineToken
    {
        public int Id { get; }

        public List<byte> Parameters { get; }

        public MessageScriptFunctionToken(int id)
        {
            Id = id;
            Parameters = new List<byte>();
        }

        public MessageScriptFunctionToken(int id, List<byte> parameters)
        {
            Id = id;
            Parameters = parameters;
        }

        public MessageScriptFunctionToken(int id, params byte[] parameters)
        {
            Id = id;
            Parameters = parameters.ToList();
        }

        // IMessageScriptToken implementation
        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.Function;
    }
}
