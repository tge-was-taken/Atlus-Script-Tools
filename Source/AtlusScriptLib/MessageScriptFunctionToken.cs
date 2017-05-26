using System.Collections.Generic;
using System.Linq;

namespace AtlusScriptLib
{
    public struct MessageScriptFunctionToken : IMessageScriptLineToken
    {
        public int FunctionTableIndex { get; }

        public int FunctionIndex { get; }

        public List<short> Arguments { get; }

        public MessageScriptFunctionToken(int functionTableIndex, int functionIndex)
        {
            FunctionTableIndex = functionTableIndex;
            FunctionIndex = functionIndex;
            Arguments = new List<short>();
        }

        public MessageScriptFunctionToken(int functionTableIndex, int functionIndex, List<short> arguments)
        {
            FunctionTableIndex = functionTableIndex;
            FunctionIndex = functionIndex;
            Arguments = arguments;
        }

        public MessageScriptFunctionToken(int functionTableIndex, int functionIndex, params short[] arguments)
        {
            FunctionTableIndex = functionTableIndex;
            FunctionIndex = functionIndex;
            Arguments = arguments.ToList();
        }

        public override string ToString()
        {
            string str = $"function {FunctionTableIndex} {FunctionIndex} ";
            if (Arguments.Count == 0)
            {
                str += "(no arguments)";
            }
            else
            {
                str += "(";
                for (int i = 0; i < Arguments.Count; i++)
                {
                    str += Arguments[i];
                    if (i + 1 != Arguments.Count)
                        str += ",";
                }
                str += ")";
            }

            return str;
        }

        // IMessageScriptToken implementation
        MessageScriptTokenType IMessageScriptLineToken.Type => MessageScriptTokenType.Function;
    }
}
