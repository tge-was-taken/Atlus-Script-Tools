using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    public struct MessageScriptFunctionToken : IMessageScriptLineToken
    {
        public int FunctionTableIndex { get; }

        public int FunctionIndex { get; }

        public List<short> Parameters { get; }

        public MessageScriptFunctionToken(int functionTableIndex, int functionIndex)
        {
            FunctionTableIndex = functionTableIndex;
            FunctionIndex = functionIndex;
            Parameters = new List<short>();
        }

        public MessageScriptFunctionToken(int functionTableIndex, int functionIndex, List<short> parameters)
        {
            FunctionTableIndex = functionTableIndex;
            FunctionIndex = functionIndex;
            Parameters = parameters;
        }

        public MessageScriptFunctionToken(int functionTableIndex, int functionIndex, params short[] parameters)
        {
            FunctionTableIndex = functionTableIndex;
            FunctionIndex = functionIndex;
            Parameters = parameters.ToList();
        }

        // IMessageScriptToken implementation
        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.Function;
    }
}
